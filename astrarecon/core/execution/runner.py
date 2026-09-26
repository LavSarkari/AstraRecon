"""DAG Execution Engine: Concurrency control, node dispatch, checkpointing, and CAS integration."""

import asyncio
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from astrarecon.core.cache.cas import ContentAddressedStore
from astrarecon.core.execution.nodes.builtins import (
    DeltaEngineNode,
    ScopeGuardNode,
    TargetInputNode,
    UnionDedupeNode,
    WildcardDetectorNode,
)
from astrarecon.core.execution.process import ProcessExecutionError, ProcessRunner
from astrarecon.core.models.session import (
    ArtifactRef,
    CheckpointDescriptor,
    NodeExecutionStatus,
    SessionSnapshot,
    SessionStatus,
)
from astrarecon.core.models.plugin import PluginManifest
from astrarecon.core.models.types import DataType
from astrarecon.core.models.workflow import WorkflowDefinition
from astrarecon.core.plugins.loader import PluginRegistry
from astrarecon.core.sessions.manager import SessionManager
from astrarecon.core.workflow.graph import WorkflowGraph


class ExecutionEngine:
    """Orchestrates asynchronous DAG workflow runs over isolated process workers."""

    def __init__(
        self,
        workflow: WorkflowDefinition,
        session_dir: Path,
        plugin_registry: PluginRegistry,
        cas: ContentAddressedStore,
        session_manager: SessionManager,
        max_concurrent_workers: int = 3,
        proxy: Optional[str] = None,
        custom_headers: Optional[list[str]] = None,
        on_node_status_change: Optional[Callable[[str, NodeExecutionStatus], None]] = None,
    ):
        self.workflow = workflow
        self.session_dir = session_dir
        self.plugin_registry = plugin_registry
        self.cas = cas
        self.session_manager = session_manager
        self.max_concurrent_workers = max_concurrent_workers
        self.proxy = proxy
        self.custom_headers = custom_headers or []
        self.on_node_status_change = on_node_status_change

        self.graph = WorkflowGraph(workflow)
        self.completed_nodes: set[str] = set()
        self.failed_nodes: set[str] = set()
        self.in_flight_nodes: set[str] = set()
        self.node_artifacts: dict[str, dict[str, Path]] = {}  # node_id -> {port_name: artifact_path}
        self.checkpoints: dict[str, CheckpointDescriptor] = {}
        self.semaphore = asyncio.Semaphore(max_concurrent_workers)

    def _update_node_status(
        self,
        node_id: str,
        status: NodeExecutionStatus,
        item_count: Optional[int] = None,
        message: Optional[str] = None,
    ) -> None:
        if self.on_node_status_change:
            try:
                self.on_node_status_change(node_id, status, item_count, message)
            except TypeError:
                try:
                    self.on_node_status_change(node_id, status, item_count)
                except TypeError:
                    self.on_node_status_change(node_id, status)

    async def run(self, resume: bool = False) -> SessionSnapshot:
        """Executes the workflow graph until all reachable nodes complete or an unrecoverable failure occurs."""
        snapshot = self.session_manager.load_session_snapshot(self.session_dir)
        snapshot.status = SessionStatus.RUNNING
        self.session_manager.save_session_snapshot(self.session_dir, snapshot)

        # If resuming, load existing checkpoints and keep only valid completed nodes
        if resume:
            self.checkpoints = self.session_manager.load_checkpoints(self.session_dir)
            valid_completed: set[str] = set()
            for node_id, cp in self.checkpoints.items():
                if cp.status == NodeExecutionStatus.COMPLETED and cp.outputs:
                    all_exist = all(Path(ref.path).exists() for ref in cp.outputs.values())
                    if all_exist:
                        valid_completed.add(node_id)

            # In a DAG, a completed node can only be reused if ALL its upstream dependencies
            # are also in valid_completed. If an upstream dependency is missing, failed,
            # or needs to re-run, downstream nodes must also re-run to process complete data.
            pruned = True
            while pruned:
                pruned = False
                for node_id in list(valid_completed):
                    upstream = self.graph.get_upstream_node_ids(node_id)
                    if upstream and not upstream.issubset(valid_completed):
                        valid_completed.remove(node_id)
                        pruned = True

            for node_id in valid_completed:
                cp = self.checkpoints[node_id]
                self.completed_nodes.add(node_id)
                self.node_artifacts[node_id] = {
                    port: Path(ref.path) for port, ref in cp.outputs.items()
                }
                cnt = sum(ref.line_count or 0 for ref in cp.outputs.values())
                dur_msg = f"{cp.duration_seconds:.1f}s" if cp.duration_seconds is not None else None
                self._update_node_status(
                    node_id,
                    NodeExecutionStatus.COMPLETED,
                    item_count=cnt if cnt > 0 else None,
                    message=dur_msg,
                )

        try:
            while (len(self.completed_nodes) + len(self.failed_nodes)) < len(self.graph.nodes):
                ready_nodes = self.graph.get_ready_frontier(
                    self.completed_nodes,
                    self.in_flight_nodes,
                    self.failed_nodes,
                )
                if not ready_nodes and not self.in_flight_nodes:
                    # Mark any remaining nodes with failed dependencies as SKIPPED
                    for nid in self.graph.nodes:
                        if nid not in self.completed_nodes and nid not in self.failed_nodes:
                            self.failed_nodes.add(nid)
                            self._update_node_status(nid, NodeExecutionStatus.SKIPPED, message="Upstream dependency failed")
                    break

                if not ready_nodes:
                    # Wait for at least one in-flight task to complete
                    await asyncio.sleep(0.1)
                    continue

                # Launch ready nodes concurrently up to semaphore limit
                for node_id in ready_nodes:
                    self.in_flight_nodes.add(node_id)
                    asyncio.create_task(self._execute_node_worker(node_id))

                await asyncio.sleep(0.05)

            # Finalize status
            if len(self.completed_nodes) == len(self.graph.nodes):
                snapshot.status = SessionStatus.COMPLETED
                snapshot.progress_percentage = 100.0
            elif self.failed_nodes:
                snapshot.status = SessionStatus.FAILED
                snapshot.progress_percentage = (len(self.completed_nodes) / max(len(self.graph.nodes), 1)) * 100.0
            else:
                snapshot.status = SessionStatus.INTERRUPTED
                snapshot.progress_percentage = (len(self.completed_nodes) / max(len(self.graph.nodes), 1)) * 100.0

        except (asyncio.CancelledError, KeyboardInterrupt):
            snapshot.status = SessionStatus.INTERRUPTED
            self.session_manager.save_session_snapshot(self.session_dir, snapshot)
            # Cancel any in-flight worker tasks
            for task in asyncio.all_tasks():
                if task is not asyncio.current_task():
                    task.cancel()
            raise
        except Exception as e:
            snapshot.status = SessionStatus.FAILED
            snapshot.error_message = str(e)
            self.session_manager.save_session_snapshot(self.session_dir, snapshot)
            raise

        self.session_manager.save_session_snapshot(self.session_dir, snapshot)
        return snapshot

    async def _execute_node_worker(self, node_id: str) -> None:
        """Executes a single node, managing checkpoints, CAS lookups, and errors."""
        async with self.semaphore:
            node = self.graph.nodes[node_id]
            self._update_node_status(node_id, NodeExecutionStatus.RUNNING)
            start_time = datetime.utcnow()

            checkpoint = CheckpointDescriptor(
                node_id=node_id,
                plugin_id=node.type,
                status=NodeExecutionStatus.RUNNING,
                started_at=start_time,
            )

            try:
                if node.type.startswith("builtin."):
                    outputs = await self._execute_builtin_node(node)
                else:
                    outputs = await self._execute_plugin_node(node)

                # Mark complete
                end_time = datetime.utcnow()
                checkpoint.status = NodeExecutionStatus.COMPLETED
                checkpoint.completed_at = end_time
                checkpoint.duration_seconds = (end_time - start_time).total_seconds()
                checkpoint.outputs = outputs
                checkpoint.exit_code = 0

                self.node_artifacts[node_id] = {k: Path(v.path) for k, v in outputs.items()}
                self.completed_nodes.add(node_id)
                self.checkpoints[node_id] = checkpoint
                self.session_manager.save_checkpoint(self.session_dir, checkpoint)

                # Compute discovered item count and write companion _urls.txt if JSONL contains URLs
                total_items = 0
                for v in outputs.values():
                    p = Path(v.path)
                    if p.is_file():
                        try:
                            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                                lines = [line.strip() for line in f if line.strip()]
                                total_items += len(lines)
                                if p.suffix == ".jsonl":
                                    urls = []
                                    for line in lines:
                                        try:
                                            d = json.loads(line)
                                            u = d.get("url") or d.get("host")
                                            if u and isinstance(u, str) and u.startswith("http"):
                                                urls.append(u)
                                        except Exception:
                                            pass
                                    if urls:
                                        companion = p.with_name(f"{p.stem}_urls.txt")
                                        companion.write_text("\n".join(urls) + "\n", encoding="utf-8")
                        except Exception:
                            pass

                self._update_node_status(
                    node_id,
                    NodeExecutionStatus.COMPLETED,
                    item_count=total_items if total_items > 0 else None,
                )

            except Exception as e:
                end_time = datetime.utcnow()
                checkpoint.status = NodeExecutionStatus.FAILED
                checkpoint.completed_at = end_time
                checkpoint.duration_seconds = (end_time - start_time).total_seconds()

                err_text = str(e)
                log_file = self.session_dir / "logs" / f"{node_id}.stderr.log"
                if log_file.exists():
                    checkpoint.error_message = f"{err_text} (Log: {log_file})"
                else:
                    checkpoint.error_message = err_text

                self.failed_nodes.add(node_id)
                self.checkpoints[node_id] = checkpoint
                self.session_manager.save_checkpoint(self.session_dir, checkpoint)

                lower_err = err_text.lower()
                if "not found in path" in lower_err or "cannot find the file" in lower_err:
                    err_msg = "Binary missing"
                elif "timed out" in lower_err:
                    err_msg = "Timed out"
                elif "rate limit" in lower_err or "429" in lower_err:
                    err_msg = "Rate limited (429)"
                elif "permission denied" in lower_err or "access is denied" in lower_err:
                    err_msg = "Permission denied"
                elif "dns" in lower_err or "resolution" in lower_err:
                    err_msg = "DNS lookup error"
                elif "connection refused" in lower_err:
                    err_msg = "Connection refused"
                elif "failed with exit code" in lower_err:
                    parts = err_text.split("failed with exit code ")
                    code = parts[1].split()[0] if len(parts) > 1 else "?"
                    err_msg = f"Failed (exit {code})"
                else:
                    err_msg = err_text.strip().split("\n")[0][:36]

                self._update_node_status(node_id, NodeExecutionStatus.FAILED, message=err_msg)
            finally:
                self.in_flight_nodes.discard(node_id)

    async def _execute_builtin_node(self, node) -> dict[str, ArtifactRef]:
        """Dispatches built-in engine node logic."""
        artifacts_dir = self.session_dir / "artifacts"
        outputs = {}

        if node.type == "builtin.target_input":
            target_str = node.config.get("raw_input") or self.workflow.id
            out_file = artifacts_dir / f"{node.id}_target.txt"
            canonical = TargetInputNode.execute(target_str, out_file)
            sha256 = self.cas.calculate_file_sha256(out_file)
            outputs["output"] = ArtifactRef(
                type=DataType.TARGET_DOMAIN,
                path=str(out_file),
                sha256=sha256,
                line_count=1,
            )

        elif node.type == "builtin.scope_guard":
            # Collect input artifact from in-edges
            in_edge = self.graph.in_edges[node.id][0]
            in_path = self.node_artifacts[in_edge.source][in_edge.source_port]
            in_scope_file = artifacts_dir / f"{node.id}_in_scope.txt"
            quarantine_file = self.session_dir / "quarantine" / "out_of_scope.txt"

            in_count, quar_count = ScopeGuardNode.execute(
                in_path,
                in_scope_file,
                quarantine_file,
                self.workflow.scope.include_patterns,
                self.workflow.scope.exclude_patterns,
            )
            sha256 = self.cas.calculate_file_sha256(in_scope_file)
            outputs["in_scope"] = ArtifactRef(
                type=DataType.FQDN,
                path=str(in_scope_file),
                sha256=sha256,
                line_count=in_count,
            )

        elif node.type == "builtin.union_dedupe":
            # Collect multiple inputs from all completed in-edges
            input_paths = [
                self.node_artifacts[edge.source][edge.source_port]
                for edge in self.graph.in_edges[node.id]
                if edge.source in self.node_artifacts and edge.source_port in self.node_artifacts[edge.source]
            ]
            out_file = artifacts_dir / f"{node.id}_deduped.txt"
            if input_paths:
                count = UnionDedupeNode.execute(input_paths, out_file)
            else:
                out_file.touch()
                count = 0
            sha256 = self.cas.calculate_file_sha256(out_file)
            outputs["output"] = ArtifactRef(
                type=DataType.FQDN,
                path=str(out_file),
                sha256=sha256,
                line_count=count,
            )

        elif node.type == "builtin.delta_engine":
            in_edge = self.graph.in_edges[node.id][0]
            current_path = self.node_artifacts[in_edge.source][in_edge.source_port]
            baseline_path = self.session_dir / "baseline.db"  # Or historical snapshot
            added_file = artifacts_dir / f"{node.id}_added.txt"

            added_count = DeltaEngineNode.execute(current_path, baseline_path, added_file)
            sha256 = self.cas.calculate_file_sha256(added_file)
            outputs["added"] = ArtifactRef(
                type=DataType.FQDN,
                path=str(added_file),
                sha256=sha256,
                line_count=added_count,
            )

        return outputs

    def _resolve_executable_path(self, manifest: PluginManifest) -> str:
        """Dynamically locates the tool binary across PATH, custom paths, and managed directories."""
        cmd = manifest.execution.command

        # 1. Absolute or relative path specified directly in command
        p = Path(cmd).expanduser()
        if p.is_file():
            return str(p.resolve())

        # 2. Check if default_path in manifest is specified and exists
        if manifest.binary and manifest.binary.default_path:
            bp = Path(manifest.binary.default_path).expanduser()
            if bp.is_file():
                return str(bp.resolve())

        # 3. Check ~/.astrarecon/bin/ (managed binaries take priority)
        managed_bin = Path.home() / ".astrarecon" / "bin"
        for candidate in [managed_bin / cmd, managed_bin / f"{cmd}.exe"]:
            if candidate.is_file():
                return str(candidate.resolve())

        # 4. Check standard Go bin paths (~/go/bin or $GOPATH/bin)
        gopath = os.environ.get("GOPATH")
        go_dirs = [Path(gopath) / "bin" if gopath else None, Path.home() / "go" / "bin"]
        for gdir in go_dirs:
            if gdir and gdir.is_dir():
                for candidate in [gdir / cmd, gdir / f"{cmd}.exe"]:
                    if candidate.is_file():
                        return str(candidate.resolve())

        # 5. Check system PATH
        which_path = shutil.which(cmd)
        if which_path:
            # Prevent conflicting Python httpx package CLI from masquerading as ProjectDiscovery httpx
            if cmd == "httpx":
                try:
                    chk = subprocess.run([which_path, "-version"], capture_output=True, text=True, timeout=2)
                    if "projectdiscovery" in (chk.stdout + chk.stderr).lower() or chk.returncode == 0:
                        return which_path
                except Exception:
                    pass
            else:
                return which_path

        # 6. Check binary name alias if distinct from command
        if manifest.binary and manifest.binary.name != cmd:
            bname = manifest.binary.name
            which_bname = shutil.which(bname)
            if which_bname:
                return which_bname
            for candidate in [managed_bin / bname, managed_bin / f"{bname}.exe"]:
                if candidate.is_file():
                    return str(candidate.resolve())

        # 7. Check if command is multi-word (e.g. "bash script.sh", "python run.py")
        tokens = cmd.strip().split()
        if len(tokens) > 1 and shutil.which(tokens[0]):
            return cmd

        # If binary is truly absent from the system, raise clear descriptive error
        raise ProcessExecutionError(
            f"Binary '{manifest.binary.name}' not found in PATH or ~/.astrarecon/bin. "
            f"Install with 'astrarecon doctor --install-missing'"
        )

    async def _execute_plugin_node(self, node) -> dict[str, ArtifactRef]:
        """Dispatches external CLI tool execution via ProcessRunner with CAS caching."""
        plugin_id = node.type.replace("plugin.", "")
        manifest = self.plugin_registry.get(plugin_id)
        if not manifest:
            raise ProcessExecutionError(f"Plugin '{plugin_id}' not found in registry")

        # Collect inputs from in-edges
        inputs_dict: dict[str, str] = {}
        inputs_content: dict[str, str] = {}
        input_hash_material = []

        for edge in self.graph.in_edges[node.id]:
            artifact_path = self.node_artifacts[edge.source][edge.source_port]
            companion = artifact_path.with_name(f"{artifact_path.stem}_urls.txt")
            if companion.exists() and companion.stat().st_size > 0:
                artifact_path = companion
            inputs_dict[edge.target_port] = str(artifact_path)
            # Read first 8KB or sha256 of input artifact
            if artifact_path.exists():
                input_hash_material.append(self.cas.calculate_file_sha256(artifact_path))
                try:
                    with open(artifact_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = [l.strip() for l in f if l.strip()]
                        if len(lines) == 1:
                            inputs_content[edge.target_port] = lines[0]
                except Exception:
                    pass

        combined_input_hash = "-".join(input_hash_material) or "seed"

        # Check CAS cache if policy is fresh
        cache_key = self.cas.compute_cache_key(
            plugin_id=manifest.id,
            plugin_version=manifest.plugin_version,
            tool_version=manifest.binary.name,
            config_dict=node.config,
            input_artifact_hash=combined_input_hash,
        )

        outputs_dir = self.session_dir / "artifacts"
        logs_dir = self.session_dir / "logs"
        outputs_refs: dict[str, ArtifactRef] = {}

        if manifest.cache.policy == "fresh":
            cache_hit = self.cas.lookup_cache(cache_key)
            if cache_hit:
                sha256, blob_path, line_count = cache_hit
                # Restore artifact via copy/link
                out_spec = manifest.outputs[0]
                target_file = outputs_dir / f"{node.id}_{out_spec.filename}"
                shutil.copy2(blob_path, target_file)

                outputs_refs[out_spec.name] = ArtifactRef(
                    type=out_spec.type,
                    path=str(target_file),
                    sha256=sha256,
                    line_count=line_count,
                    cas_path=str(blob_path),
                )
                return outputs_refs

        # Prepare outputs paths for command substitution
        output_substitutions: dict[str, str] = {}
        for out_spec in manifest.outputs:
            dest_file = outputs_dir / f"{node.id}_{out_spec.filename}"
            output_substitutions[out_spec.name] = str(dest_file)

        # Check if all input artifacts are empty (0 lines)
        total_input_lines = 0
        for in_port, in_path_str in inputs_dict.items():
            in_file = Path(in_path_str)
            if in_file.exists():
                try:
                    with open(in_file, "r", encoding="utf-8", errors="ignore") as f:
                        total_input_lines += sum(1 for line in f if line.strip())
                except Exception:
                    pass

        # If plugin expects inputs, but all input files are 0 lines, produce empty outputs without failing
        if manifest.inputs and total_input_lines == 0:
            for out_spec in manifest.outputs:
                dest_file = Path(output_substitutions[out_spec.name])
                dest_file.touch()
                outputs_refs[out_spec.name] = ArtifactRef(
                    type=out_spec.type,
                    path=str(dest_file),
                    sha256=self.cas.calculate_file_sha256(dest_file),
                    line_count=0,
                )
            return outputs_refs

        # Build command arguments vector with smart path resolution
        cmd_args = [self._resolve_executable_path(manifest)]
        for arg in manifest.execution.args:
            resolved_arg = arg
            # Replace inputs (use string content for source="param", file path for source="artifact")
            for in_key, in_val in inputs_dict.items():
                is_param_input = any(
                    inp.name == in_key and getattr(inp, "source", "param") == "param"
                    for inp in manifest.inputs
                )
                if is_param_input and in_key in inputs_content:
                    resolved_arg = resolved_arg.replace(f"{{inputs.{in_key}}}", inputs_content[in_key])
                else:
                    resolved_arg = resolved_arg.replace(f"{{inputs.{in_key}}}", in_val)
            # Replace outputs
            for out_key, out_val in output_substitutions.items():
                resolved_arg = resolved_arg.replace(f"{{outputs.{out_key}}}", out_val)
            cmd_args.append(resolved_arg)

        # Apply global proxy & headers if applicable
        if self.proxy:
            if manifest.id in ("httpx", "nuclei"):
                cmd_args.extend(["-proxy", self.proxy])

        for h in self.custom_headers:
            if manifest.id in ("httpx", "nuclei"):
                cmd_args.extend(["-H", h])

        stdout_log = logs_dir / f"{node.id}.stdout.log"
        stderr_log = logs_dir / f"{node.id}.stderr.log"

        exit_code = await ProcessRunner.run_command_stream(
            cmd_args=cmd_args,
            stdout_path=stdout_log,
            stderr_path=stderr_log,
            timeout_seconds=manifest.execution.timeout_seconds,
        )

        if exit_code != 0:
            err_sample = ""
            if stderr_log.exists():
                with open(stderr_log, "r", encoding="utf-8", errors="ignore") as f:
                    err_sample = f.read(1000).strip()

            hint = ""
            lower_err = err_sample.lower()
            if "permission denied" in lower_err or "access is denied" in lower_err:
                hint = " (Permission denied)"
            elif "rate limit" in lower_err or "429" in lower_err or "too many requests" in lower_err:
                hint = " (Rate limited - HTTP 429)"
            elif "dial tcp: lookup" in lower_err or "no such host" in lower_err:
                hint = " (DNS lookup failed)"
            elif "connection refused" in lower_err:
                hint = " (Connection refused)"

            raise ProcessExecutionError(
                f"Tool '{manifest.id}' failed with exit code {exit_code}{hint}",
                exit_code=exit_code,
                stderr=err_sample,
            )

        # Commit produced outputs to CAS
        for out_spec in manifest.outputs:
            dest_file = Path(output_substitutions[out_spec.name])
            if (not dest_file.exists() or dest_file.stat().st_size == 0) and stdout_log.exists() and stdout_log.stat().st_size > 0:
                # Capture tool stdout stream if tool writes directly to stdout (e.g. assetfinder)
                shutil.copy2(stdout_log, dest_file)
            elif not dest_file.exists():
                # Touch empty file if tool produced no items
                dest_file.touch()

            sha256, blob_path = self.cas.record_cache_entry(
                cache_key=cache_key,
                plugin_id=manifest.id,
                plugin_version=manifest.plugin_version,
                tool_version=manifest.binary.name,
                artifact_file=dest_file,
                ttl_hours=manifest.cache.default_ttl_hours,
            )

            count = 0
            if dest_file.is_file():
                try:
                    with open(dest_file, "r", encoding="utf-8", errors="ignore") as f:
                        count = sum(1 for line in f if line.strip())
                except Exception:
                    pass

            outputs_refs[out_spec.name] = ArtifactRef(
                type=out_spec.type,
                path=str(dest_file),
                sha256=sha256,
                line_count=count,
                cas_path=str(blob_path),
            )

        return outputs_refs
