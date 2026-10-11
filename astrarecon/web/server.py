"""Lightweight, zero-overhead Web Server for AstraRecon Visual Canvas & Dashboard.

Designed for resource-constrained environments (runs smoothly on a $3.50 VPS with < 20MB RAM).
Built entirely on Python standard library http.server, with SSE for real-time DAG telemetry.
"""

from __future__ import annotations

import asyncio
import json
import mimetypes
import os
import queue
import shutil
import sys
import threading
import time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, unquote, urlparse

from astrarecon import __version__
from astrarecon.cli.scan import build_workflow
from astrarecon.core.cache.cas import ContentAddressedStore
from astrarecon.core.doctor.inspector import EnvironmentInspector
from astrarecon.core.execution.runner import ExecutionEngine
from astrarecon.core.models.session import EnvFingerprint, NodeExecutionStatus, SessionStatus
from astrarecon.core.plugins.loader import PluginLoader
from astrarecon.core.reports.ai_export import AIDistillationEngine
from astrarecon.core.reports.output_writer import OutputFormat, OutputWriter
from astrarecon.core.reports.result_renderer import ScanResultLoader
from astrarecon.core.sessions.manager import SessionManager
from astrarecon.core.validation import validate_target


STATIC_DIR = Path(__file__).parent / "static"


class ScanController:
    """Manages active scan thread, state telemetry, and SSE broadcast channels."""

    def __init__(self):
        self.lock = threading.Lock()
        self.is_scanning = False
        self.active_session_id: Optional[str] = None
        self.active_target: Optional[str] = None
        self.active_workflow_id: Optional[str] = None
        self.start_time: Optional[float] = None
        self.node_statuses: dict[str, dict[str, Any]] = {}
        self.recent_logs: list[dict[str, Any]] = []
        self.subscribers: set[queue.Queue] = set()
        self._current_engine: Optional[ExecutionEngine] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._scan_loop: Optional[asyncio.AbstractEventLoop] = None
        self._main_scan_task: Optional[asyncio.Task] = None
        self.active_nodes: list[dict[str, Any]] = []
        self.active_edges: list[dict[str, Any]] = []
        self._stop_requested = False

        # Hydrate latest session if present
        try:
            mgr = SessionManager()
            if mgr.base_dir.exists():
                candidates = sorted(
                    [d for d in mgr.base_dir.iterdir() if d.is_dir() and (d / "session.json").exists()],
                    key=lambda x: x.stat().st_mtime,
                    reverse=True
                )
                if candidates:
                    self.active_session_id = candidates[0].name
                    snap = mgr.load_session_snapshot(candidates[0])
                    self.active_target = snap.target
        except Exception:
            pass

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=100)
        with self.lock:
            self.subscribers.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.lock:
            self.subscribers.discard(q)

    def broadcast(self, event_type: str, data: Any) -> None:
        payload = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
        with self.lock:
            dead = set()
            for q in self.subscribers:
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    dead.add(q)
                except Exception:
                    dead.add(q)
            self.subscribers.difference_update(dead)

    def log(self, message: str, level: str = "info", node_id: Optional[str] = None) -> None:
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "message": message,
            "level": level,
            "node_id": node_id,
        }
        with self.lock:
            self.recent_logs.append(entry)
            if len(self.recent_logs) > 500:
                self.recent_logs.pop(0)
        self.broadcast("log", entry)

    def update_node(
        self,
        node_id: str,
        status: Any,
        item_count: Optional[int] = None,
        message: Optional[str] = None,
    ) -> None:
        status_str = status.value if hasattr(status, "value") else str(status).upper()
        with self.lock:
            current = self.node_statuses.setdefault(node_id, {})
            current["status"] = status_str
            if item_count is not None:
                current["item_count"] = item_count
            if message is not None:
                current["message"] = message
            current["updated_at"] = time.time()
            if self.start_time:
                current["elapsed"] = round(time.time() - self.start_time, 1)

        self.broadcast("node_update", {
            "node_id": node_id,
            "status": status_str,
            "item_count": item_count,
            "message": message,
        })

    def start_scan(
        self,
        target: str,
        workflow: str = "default",
        profile: str = "auto",
        proxy: Optional[str] = None,
        custom_tools: Optional[list[str]] = None,
        skip_tools: Optional[list[str]] = None,
        with_tools: Optional[list[str]] = None,
        scope_include: Optional[str] = None,
        scope_exclude: Optional[str] = None,
    ) -> dict[str, Any]:
        with self.lock:
            if self.is_scanning:
                return {"error": "A scan is already actively running."}

            is_valid, normalized, err = validate_target(target)
            if not is_valid:
                return {"error": f"Invalid target: {err}"}

            # Auto-merge disabled tools from configuration
            cfg = _load_plugins_config()
            active_disabled = list(cfg.get("disabled_tools", []))
            if skip_tools:
                active_disabled = list(set(active_disabled + skip_tools))

            self.is_scanning = True
            self.active_target = normalized
            self.active_workflow_id = workflow
            self.start_time = time.time()
            self.node_statuses = {}
            self.recent_logs.clear()
            self._stop_requested = False

        thread = threading.Thread(
            target=self._run_scan_thread,
            args=(
                normalized,
                workflow,
                profile,
                proxy,
                custom_tools,
                active_disabled,
                with_tools,
                scope_include,
                scope_exclude,
            ),
            daemon=True,
        )
        self._scan_thread = thread
        thread.start()

        return {
            "status": "started",
            "target": normalized,
            "workflow": workflow,
        }

    def stop_scan(self) -> dict[str, Any]:
        with self.lock:
            if not self.is_scanning:
                return {"status": "not_running"}
            self._stop_requested = True
            if self._current_engine and hasattr(self._current_engine, "cancel"):
                try:
                    self._current_engine.cancel()
                except Exception:
                    pass
            if self._scan_loop and self._scan_loop.is_running():
                if self._main_scan_task and not self._main_scan_task.done():
                    try:
                        self._scan_loop.call_soon_threadsafe(self._main_scan_task.cancel)
                    except Exception:
                        pass
        self.log("Mission abort signal acknowledged. Halting worker processes...", level="warning")
        return {"status": "stopping"}

    def _run_scan_thread(
        self,
        target: str,
        preset: str,
        profile: str,
        proxy: Optional[str],
        custom_tools: Optional[list[str]],
        skip_tools: Optional[list[str]],
        with_tools: Optional[list[str]],
        scope_include: Optional[str],
        scope_exclude: Optional[str],
    ) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        with self.lock:
            self._scan_loop = loop

        try:
            self.log(f"Assembling reconnaissance flight plan for target {target} ({preset})...")
            wf = build_workflow(
                target=target,
                preset=preset,
                scope_include=scope_include,
                scope_exclude=scope_exclude,
                with_tools=with_tools,
                skip_tools=skip_tools,
                custom_tools=custom_tools,
            )

            session_mgr = SessionManager()
            cas = ContentAddressedStore()
            plugin_registry = PluginLoader.load_all_plugins()
            env = EnvironmentInspector.inspect()

            if self._stop_requested:
                raise asyncio.CancelledError("Mission was aborted before engine dispatch.")

            fp = EnvFingerprint(
                captured_at=datetime.utcnow(),
                os_distro=env.os_name,
                os_version=env.os_version,
                kernel=env.kernel,
                arch=env.arch,
                python_version=env.python_version,
                go_version=env.go_version,
                tools={name: status.version or "installed" for name, status in env.tools.items() if status.installed},
            )

            session_dir = session_mgr.create_session(target=target, workflow=wf, fingerprint=fp)
            nodes_data = [
                {
                    "id": n.id,
                    "type": n.type,
                    "label": n.id.replace("_", " ").title(),
                }
                for n in wf.nodes
            ]
            edges_data = [
                {
                    "source": e.source,
                    "target": e.target,
                    "source_port": e.source_port,
                    "target_port": e.target_port,
                }
                for e in wf.edges
            ]

            with self.lock:
                self.active_session_id = session_dir.name
                self.active_nodes = nodes_data
                self.active_edges = edges_data
                for n in wf.nodes:
                    self.node_statuses[n.id] = {
                        "status": "WAITING",
                        "label": n.id.replace("_", " ").title(),
                        "type": n.type,
                    }

            self.broadcast("scan_init", {
                "session_id": session_dir.name,
                "target": target,
                "workflow_id": wf.id,
                "nodes": nodes_data,
                "edges": edges_data,
            })

            if self._stop_requested:
                raise asyncio.CancelledError("Mission was aborted before engine dispatch.")

            workers = 3
            if profile == "safe":
                workers = 1
            elif profile == "beast":
                workers = 5

            def status_cb(node_id: str, status: Any, item_count: Optional[int] = None, message: Optional[str] = None):
                self.update_node(node_id, status, item_count, message)
                status_name = status.value if hasattr(status, "value") else str(status)
                msg_suffix = f" - {message}" if message else ""
                cnt_suffix = f" ({item_count} items)" if item_count else ""
                self.log(f"Node [{node_id}] status -> {status_name}{cnt_suffix}{msg_suffix}")

            engine = ExecutionEngine(
                workflow=wf,
                session_dir=session_dir,
                plugin_registry=plugin_registry,
                cas=cas,
                session_manager=session_mgr,
                max_concurrent_workers=workers,
                proxy=proxy,
                on_node_status_change=status_cb,
            )
            with self.lock:
                self._current_engine = engine
                self._main_scan_task = loop.create_task(engine.run(resume=False))
                if self._stop_requested:
                    engine.cancel()
                    self._main_scan_task.cancel()

            self.log("Dispatching DAG workers onto topological frontiers...")
            snapshot = loop.run_until_complete(self._main_scan_task)

            # Trigger AI distillation bundle export
            try:
                AIDistillationEngine.export_bundle(
                    target=target,
                    session_dir=session_dir,
                    output_dir=session_dir / "exports",
                )
            except Exception:
                pass

            # Load structured results
            results = ScanResultLoader.load(session_dir=session_dir, target=target)
            self.broadcast("scan_complete", {
                "session_id": session_dir.name,
                "target": target,
                "status": snapshot.status.value,
                "subdomain_count": results.subdomain_count,
                "live_host_count": results.live_host_count,
                "finding_count": results.finding_count,
                "duration_seconds": round(time.time() - (self.start_time or time.time()), 1),
            })
            self.log(
                f"Scan finished! Discovered {results.subdomain_count} subdomains, "
                f"{results.live_host_count} live hosts, {results.finding_count} vulnerabilities.",
                level="success",
            )

        except (asyncio.CancelledError, KeyboardInterrupt):
            self.log("Mission aborted by operator.", level="warning")
            with self.lock:
                for nid, st in self.node_statuses.items():
                    if st.get("status") in ("RUNNING", "WAITING"):
                        st["status"] = "CANCELLED"
                        st["message"] = "Aborted"
            self.broadcast("scan_cancelled", {
                "session_id": session_dir.name if 'session_dir' in locals() else None,
                "target": target,
            })
        except Exception as e:
            self.log(f"Scan execution error: {e}", level="error")
            self.broadcast("scan_error", {"error": str(e), "target": target})
        finally:
            with self.lock:
                self.is_scanning = False
                self._current_engine = None
                self._main_scan_task = None
                self._scan_loop = None
                self._stop_requested = False
            try:
                loop.close()
            except Exception:
                pass

    def get_status(self) -> dict[str, Any]:
        with self.lock:
            elapsed = round(time.time() - self.start_time, 1) if self.start_time and self.is_scanning else 0.0
            data = {
                "is_scanning": self.is_scanning,
                "active_session_id": self.active_session_id,
                "active_target": self.active_target,
                "active_workflow_id": self.active_workflow_id,
                "elapsed_seconds": elapsed,
                "node_statuses": dict(self.node_statuses),
                "server_version": __version__,
            }
            if self.is_scanning:
                data["nodes"] = list(self.active_nodes)
                data["edges"] = list(self.active_edges)
            return data


def _get_projects_file() -> Path:
    p = Path.home() / ".astrarecon" / "projects.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _load_projects() -> list[dict[str, Any]]:
    p = _get_projects_file()
    if not p.exists():
        default_proj = [
            {
                "id": "default",
                "name": "Global Engagement",
                "target": "example.com",
                "disabled_tools": [],
                "created_at": datetime.utcnow().isoformat(),
                "last_run": None,
            }
        ]
        _save_projects(default_proj)
        return default_proj
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_projects(projects: list[dict[str, Any]]) -> None:
    p = _get_projects_file()
    p.write_text(json.dumps(projects, indent=2), encoding="utf-8")


def _get_plugins_config_file() -> Path:
    p = Path.home() / ".astrarecon" / "plugins_config.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _load_plugins_config() -> dict[str, Any]:
    p = _get_plugins_config_file()
    if not p.exists():
        default_cfg = {
            "disabled_tools": [],
            "project_overrides": {},
            "custom_plugins": []
        }
        _save_plugins_config(default_cfg)
        return default_cfg
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"disabled_tools": [], "project_overrides": {}, "custom_plugins": []}


def _save_plugins_config(config: dict[str, Any]) -> None:
    p = _get_plugins_config_file()
    p.write_text(json.dumps(config, indent=2), encoding="utf-8")


CONTROLLER = ScanController()


class AstraRequestHandler(BaseHTTPRequestHandler):
    """Handles REST API and static asset requests with zero overhead."""

    server_version = "AstraRecon-WebServer/" + __version__

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self.end_headers()

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # -------------------------------------------------------------
        # Server-Sent Events (SSE) Stream
        # -------------------------------------------------------------
        if path == "/api/events":
            self._handle_events()
            return

        # -------------------------------------------------------------
        # REST API Routes
        # -------------------------------------------------------------
        if path == "/api/status":
            self._send_json(CONTROLLER.get_status())
            return

        if path == "/api/system" or path == "/api/doctor":
            env = EnvironmentInspector.inspect()
            tools_data = {}
            for name, status in env.tools.items():
                tools_data[name] = {
                    "installed": status.installed,
                    "version": status.version,
                    "path": status.path,
                    "error": status.error,
                }
            self._send_json({
                "os_name": env.os_name,
                "os_version": env.os_version,
                "arch": env.arch,
                "python_version": env.python_version,
                "go_installed": env.go_installed,
                "go_version": env.go_version,
                "tools": tools_data,
                "installed_count": sum(1 for s in env.tools.values() if s.installed),
                "total_tools": len(env.tools),
            })
            return

        if path == "/api/plugins":
            registry = PluginLoader.load_all_plugins()
            plugins = []
            for p in registry.list_all():
                plugins.append({
                    "id": p.id,
                    "name": p.name,
                    "version": p.plugin_version,
                    "stage": p.stage,
                    "description": p.description,
                    "author": p.author,
                    "binary": p.binary.name if p.binary else None,
                    "inputs": [{"name": i.name, "type": str(i.type)} for i in p.inputs],
                    "outputs": [{"name": o.name, "type": str(o.type), "format": o.format} for o in p.outputs],
                })
            self._send_json(plugins)
            return

        if path == "/api/presets":
            self._send_json([
                {
                    "id": "default",
                    "name": "Default Deep Recon (7-Stage)",
                    "description": "Full end-to-end OSINT, active DNS, live probing, JS crawling & vulnerability audit.",
                    "stages": ["Subdomains", "DNS", "Live Hosts", "Ports", "Crawling", "JS Analysis", "Vulns"],
                },
                {
                    "id": "fast",
                    "name": "Fast Surface Triage",
                    "description": "Rapid passive enumeration and live HTTP host probing without deep crawling.",
                    "stages": ["Subdomains", "DNS", "Live Hosts"],
                },
                {
                    "id": "passive",
                    "name": "Stealth Passive OSINT",
                    "description": "Zero packets sent directly to target infrastructure. Pure third-party database reconnaissance.",
                    "stages": ["Subdomains", "Historical URLs"],
                },
                {
                    "id": "vuln",
                    "name": "Direct Vulnerability Assessment",
                    "description": "Nuclei & Dalfox security template verification on discovered endpoints.",
                    "stages": ["Live Hosts", "Crawling", "Nuclei", "Dalfox"],
                },
            ])
            return

        if path == "/api/projects":
            self._send_json(_load_projects())
            return

        if path == "/api/projects/recent":
            mgr = SessionManager()
            recent_list = []
            if mgr.base_dir.exists():
                for d in sorted(mgr.base_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True)[:5]:
                    if d.is_dir() and (d / "session.json").exists():
                        try:
                            snap = mgr.load_session_snapshot(d)
                            res = ScanResultLoader.load(d, snap.target)
                            recent_list.append({
                                "session_id": d.name,
                                "target": snap.target,
                                "status": snap.status.value,
                                "subdomains": res.subdomain_count,
                                "live_hosts": res.live_host_count,
                                "findings": res.finding_count,
                                "created_at": snap.created_at.isoformat() if hasattr(snap.created_at, "isoformat") else str(snap.created_at),
                            })
                        except Exception:
                            pass
            self._send_json({
                "recent_targets": recent_list,
                "projects": _load_projects(),
            })
            return

        if path == "/api/plugins/config":
            self._send_json(_load_plugins_config())
            return

        if path == "/api/sessions":
            mgr = SessionManager()
            sessions = []
            if mgr.base_dir.exists():
                for d in sorted(mgr.base_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
                    if d.is_dir() and (d / "session.json").exists():
                        try:
                            snap = mgr.load_session_snapshot(d)
                            res = ScanResultLoader.load(d, snap.target)
                            sessions.append({
                                "id": d.name,
                                "target": snap.target,
                                "status": snap.status.value,
                                "started_at": snap.created_at.isoformat() if hasattr(snap.created_at, "isoformat") else str(snap.created_at),
                                "subdomains": res.subdomain_count,
                                "live_hosts": res.live_host_count,
                                "findings": res.finding_count,
                                "progress": snap.progress_percentage,
                            })
                        except Exception:
                            pass
            self._send_json(sessions)
            return

        if path.startswith("/api/session/"):
            parts = path.strip("/").split("/")
            if len(parts) >= 3:
                session_id = parts[2]
                mgr = SessionManager()
                s_dir = mgr.base_dir / session_id

                if not s_dir.exists():
                    self._send_json({"error": "Session not found"}, status=404)
                    return

                # /api/session/<id>
                if len(parts) == 3:
                    snap = mgr.load_session_snapshot(s_dir)
                    checkpoints = mgr.load_checkpoints(s_dir)
                    wf_file = s_dir / "workflow.json"
                    wf_data = json.loads(wf_file.read_text(encoding="utf-8")) if wf_file.exists() else None

                    # Format checkpoints
                    cp_data = {}
                    for nid, cp in checkpoints.items():
                        cp_data[nid] = {
                            "status": cp.status.value,
                            "started_at": cp.started_at.isoformat() if cp.started_at else None,
                            "completed_at": cp.completed_at.isoformat() if cp.completed_at else None,
                            "duration_seconds": cp.duration_seconds,
                            "error": cp.error_message,
                            "outputs": {
                                port: {
                                    "type": str(ref.type),
                                    "path": ref.path,
                                    "lines": ref.line_count,
                                }
                                for port, ref in (cp.outputs or {}).items()
                            },
                        }

                    self._send_json({
                        "id": session_id,
                        "target": snap.target,
                        "status": snap.status.value,
                        "progress": snap.progress_percentage,
                        "created_at": snap.created_at.isoformat() if hasattr(snap.created_at, "isoformat") else str(snap.created_at),
                        "workflow": wf_data,
                        "checkpoints": cp_data,
                    })
                    return

                # /api/session/<id>/results
                if len(parts) == 4 and parts[3] == "results":
                    snap = mgr.load_session_snapshot(s_dir)
                    res = ScanResultLoader.load(s_dir, snap.target)
                    self._send_json({
                        "target": res.target,
                        "subdomains": res.subdomains[:1000],
                        "total_subdomains": res.subdomain_count,
                        "live_hosts": res.live_hosts[:500],
                        "total_live_hosts": res.live_host_count,
                        "findings": res.findings[:500],
                        "total_findings": res.finding_count,
                    })
                    return

                # /api/session/<id>/logs/<node_id>
                if len(parts) == 5 and parts[3] == "logs":
                    node_id = parts[4]
                    stdout_f = s_dir / "logs" / f"{node_id}.stdout.log"
                    stderr_f = s_dir / "logs" / f"{node_id}.stderr.log"
                    out_text = stdout_f.read_text(encoding="utf-8", errors="ignore") if stdout_f.exists() else ""
                    err_text = stderr_f.read_text(encoding="utf-8", errors="ignore") if stderr_f.exists() else ""
                    self._send_json({
                        "node_id": node_id,
                        "stdout": out_text[-20000:],
                        "stderr": err_text[-20000:],
                    })
                    return

                # /api/session/<id>/export/<format>
                if len(parts) == 5 and parts[3] == "export":
                    fmt = parts[4].lower()
                    snap = mgr.load_session_snapshot(s_dir)
                    res = ScanResultLoader.load(s_dir, snap.target)

                    if fmt == "ai":
                        ai_dir = s_dir / "exports" / "ai"
                        if not ai_dir.exists():
                            AIDistillationEngine.export_bundle(snap.target, s_dir, s_dir / "exports")
                        zip_dest = s_dir / f"{session_id}_ai_bundle.zip"
                        shutil.make_archive(str(s_dir / f"{session_id}_ai_bundle"), "zip", str(ai_dir))
                        self._serve_file(zip_dest, "application/zip", as_attachment=True)
                        return

                    tmp_out = s_dir / f"export.{fmt}"
                    if fmt == "json":
                        OutputWriter.write(res, tmp_out, OutputFormat.JSON)
                        self._serve_file(tmp_out, "application/json", as_attachment=True)
                    elif fmt == "csv":
                        OutputWriter.write(res, tmp_out, OutputFormat.CSV)
                        self._serve_file(tmp_out, "text/csv", as_attachment=True)
                    elif fmt in ("md", "markdown"):
                        OutputWriter.write(res, tmp_out, OutputFormat.MARKDOWN)
                        self._serve_file(tmp_out, "text/markdown", as_attachment=True)
                    elif fmt == "txt":
                        sub_file = s_dir / "artifacts" / "subdomains.txt"
                        if not sub_file.exists():
                            sub_file.write_text("\n".join(res.subdomains) + "\n", encoding="utf-8")
                        self._serve_file(sub_file, "text/plain", as_attachment=True)
                    else:
                        self._send_json({"error": "Unsupported export format"}, status=400)
                    return

        # -------------------------------------------------------------
        # Static Asset Serving
        # -------------------------------------------------------------
        self._serve_static(path)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length > 0 else b"{}"

        try:
            body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception:
            self._send_json({"error": "Invalid JSON body"}, status=400)
            return

        if path == "/api/scan/start":
            target = body.get("target", "").strip()
            if not target:
                self._send_json({"error": "Target domain/URL is required"}, status=400)
                return

            workflow = body.get("workflow", "default")
            profile = body.get("profile", "auto")
            proxy = body.get("proxy", "").strip() or None
            custom_tools = body.get("custom_tools") or None
            skip_tools = body.get("skip_tools") or None
            with_tools = body.get("with_tools") or None
            scope_inc = body.get("scope_include", "").strip() or None
            scope_exc = body.get("scope_exclude", "").strip() or None

            res = CONTROLLER.start_scan(
                target=target,
                workflow=workflow,
                profile=profile,
                proxy=proxy,
                custom_tools=custom_tools,
                skip_tools=skip_tools,
                with_tools=with_tools,
                scope_include=scope_inc,
                scope_exclude=scope_exc,
            )
            self._send_json(res, status=200 if "error" not in res else 400)
            return

        if path == "/api/scan/stop":
            res = CONTROLLER.stop_scan()
            self._send_json(res)
            return

        if path == "/api/projects":
            projects = _load_projects()
            p_id = body.get("id") or f"proj_{int(time.time())}"
            p_name = body.get("name", "New Project").strip()
            p_target = body.get("target", "").strip()
            p_disabled = body.get("disabled_tools", [])

            found = False
            for p in projects:
                if p["id"] == p_id:
                    p["name"] = p_name
                    if p_target: p["target"] = p_target
                    p["disabled_tools"] = p_disabled
                    found = True
                    break
            if not found:
                projects.insert(0, {
                    "id": p_id,
                    "name": p_name,
                    "target": p_target,
                    "disabled_tools": p_disabled,
                    "created_at": datetime.utcnow().isoformat(),
                    "last_run": None,
                })
            _save_projects(projects)
            self._send_json({"status": "saved", "project_id": p_id, "projects": projects})
            return

        if path == "/api/plugins/toggle":
            tool_id = body.get("tool_id", "").strip().lower()
            enabled = bool(body.get("enabled", True))
            scope = body.get("scope", "global")
            project_id = body.get("project_id", "default")

            if not tool_id:
                self._send_json({"error": "tool_id is required"}, status=400)
                return

            cfg = _load_plugins_config()
            if scope == "global":
                disabled = set(cfg.get("disabled_tools", []))
                if enabled:
                    disabled.discard(tool_id)
                else:
                    disabled.add(tool_id)
                cfg["disabled_tools"] = sorted(list(disabled))
            else:
                overrides = cfg.setdefault("project_overrides", {}).setdefault(project_id, {})
                proj_disabled = set(overrides.get("disabled_tools", []))
                if enabled:
                    proj_disabled.discard(tool_id)
                else:
                    proj_disabled.add(tool_id)
                overrides["disabled_tools"] = sorted(list(proj_disabled))

            _save_plugins_config(cfg)
            self._send_json({"status": "updated", "config": cfg})
            return

        if path == "/api/plugins/custom":
            name = body.get("name", "").strip().lower()
            command = body.get("command", "").strip()
            input_type = body.get("input_type", "TargetDomain").strip()
            output_type = body.get("output_type", "FQDN").strip()

            if not name or not command:
                self._send_json({"error": "name and command are required"}, status=400)
                return

            user_plugin_dir = PluginLoader.get_user_plugin_dir() / name
            user_plugin_dir.mkdir(parents=True, exist_ok=True)
            manifest_yaml = f"""id: "{name}"
name: "{name.title()}"
version: "1.0.0"
author: "User Custom"
description: "User registered custom script tool."
binary: "{command.split()[0]}"
command_template: "{command}"
inputs:
  - name: "input_target"
    type: "{input_type}"
outputs:
  - name: "output_results"
    type: "{output_type}"
"""
            (user_plugin_dir / "plugin.yaml").write_text(manifest_yaml, encoding="utf-8")

            cfg = _load_plugins_config()
            custom_list = cfg.setdefault("custom_plugins", [])
            custom_list.append({"name": name, "command": command, "input_type": input_type, "output_type": output_type})
            _save_plugins_config(cfg)

            self._send_json({"status": "created", "plugin_id": name})
            return

        if path == "/api/sessions/clear":
            target = body.get("target") if isinstance(body, dict) else None
            mgr = SessionManager()
            deleted, reclaimed = mgr.clear_sessions(target=target)
            if not CONTROLLER.is_scanning:
                CONTROLLER.active_session_id = None
                CONTROLLER.active_target = None
            self._send_json({"status": "cleared", "deleted_count": deleted, "reclaimed_bytes": reclaimed})
            return

        if path.startswith("/api/session/") and path.endswith("/delete"):
            session_id = path.replace("/api/session/", "").replace("/delete", "").strip().strip("/")
            if CONTROLLER.is_scanning and CONTROLLER.active_session_id == session_id:
                self._send_json({"error": "Cannot delete active running mission. Please abort the mission first."}, status=400)
                return

            mgr = SessionManager()
            success = mgr.delete_session(session_id)
            if success:
                if CONTROLLER.active_session_id == session_id:
                    CONTROLLER.active_session_id = None
                    CONTROLLER.active_target = None
                self._send_json({"status": "deleted", "session_id": session_id})
            else:
                self._send_json({"error": "Session not found"}, status=404)
            return

        self._send_json({"error": "Not Found"}, status=404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # Purge all mission history / by target
        if path == "/api/sessions":
            target = query.get("target", [None])[0]
            mgr = SessionManager()
            deleted, reclaimed = mgr.clear_sessions(target=target)
            if not CONTROLLER.is_scanning:
                CONTROLLER.active_session_id = None
                CONTROLLER.active_target = None
            self._send_json({"status": "cleared", "deleted_count": deleted, "reclaimed_bytes": reclaimed})
            return

        # Delete single mission
        if path.startswith("/api/session/"):
            session_id = path.replace("/api/session/", "").strip().strip("/")
            if CONTROLLER.is_scanning and CONTROLLER.active_session_id == session_id:
                self._send_json({"error": "Cannot delete active running mission. Please abort the mission first."}, status=400)
                return

            mgr = SessionManager()
            success = mgr.delete_session(session_id)
            if success:
                if CONTROLLER.active_session_id == session_id:
                    CONTROLLER.active_session_id = None
                    CONTROLLER.active_target = None
                self._send_json({"status": "deleted", "session_id": session_id})
            else:
                self._send_json({"error": "Session not found"}, status=404)
            return

        self._send_json({"error": "Not Found"}, status=404)

    def _handle_events(self):
        """Streams Server-Sent Events (SSE) to connected frontend clients."""
        self.send_response(HTTPStatus.OK)
        self._send_cors_headers()
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        q = CONTROLLER.subscribe()
        try:
            # Send initial state snapshot
            initial_status = CONTROLLER.get_status()
            self.wfile.write(f"event: init\ndata: {json.dumps(initial_status)}\n\n".encode("utf-8"))
            self.wfile.flush()

            # Replay recent log buffer so refreshed or new tabs instantly see active progress
            with CONTROLLER.lock:
                buffered_logs = list(CONTROLLER.recent_logs)
            if buffered_logs:
                self.wfile.write(f"event: log_history\ndata: {json.dumps(buffered_logs)}\n\n".encode("utf-8"))
                self.wfile.flush()

            while True:
                try:
                    payload = q.get(timeout=10.0)
                    self.wfile.write(payload.encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    # Keepalive ping
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            CONTROLLER.unsubscribe(q)

    def _serve_static(self, path: str):
        if path == "/" or path == "":
            rel_path = "index.html"
        else:
            rel_path = path.lstrip("/")

        target_file = (STATIC_DIR / rel_path).resolve()

        # Prevent directory traversal
        if not str(target_file).startswith(str(STATIC_DIR.resolve())):
            self._send_json({"error": "Forbidden"}, status=403)
            return

        # Special fallback for logo.png in repo root
        if not target_file.exists() and rel_path == "logo.png":
            repo_logo = Path(__file__).resolve().parent.parent.parent / "logo.png"
            if repo_logo.exists():
                self._serve_file(repo_logo, "image/png")
                return

        if not target_file.is_file():
            # SPA fallback: if requesting non-api route, serve index.html
            target_file = STATIC_DIR / "index.html"
            if not target_file.is_file():
                self._send_json({"error": "Not Found"}, status=404)
                return

        mime_type, _ = mimetypes.guess_type(str(target_file))
        mime_type = mime_type or "application/octet-stream"
        self._serve_file(target_file, mime_type)

    def _serve_file(self, file_path: Path, mime_type: str, as_attachment: bool = False):
        try:
            file_bytes = file_path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self._send_cors_headers()
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(file_bytes)))
            if as_attachment:
                self.send_header("Content-Disposition", f'attachment; filename="{file_path.name}"')
            self.end_headers()
            self.wfile.write(file_bytes)
        except Exception:
            self._send_json({"error": "Failed to read file"}, status=500)

    def log_message(self, format, *args):
        # Suppress noisy standard HTTP access logs to keep terminal quiet
        pass


class AstraWebServer:
    """Wraps the ThreadingHTTPServer with port scanning and background runner."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, daemon: bool = False) -> int:
        """Starts web server, trying sequential ports if chosen port is occupied."""
        attempt_port = self.port
        max_attempts = 10
        for _ in range(max_attempts):
            try:
                self.server = ThreadingHTTPServer((self.host, attempt_port), AstraRequestHandler)
                self.port = attempt_port
                break
            except OSError:
                attempt_port += 1

        if not self.server:
            raise RuntimeError(f"Could not bind AstraRecon web server to {self.host}:{self.port}")

        if daemon:
            self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self._thread.start()
        else:
            self.server.serve_forever()

        return self.port

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()


def start_web_server(host: str = "127.0.0.1", port: int = 8080, daemon: bool = False) -> tuple[AstraWebServer, int]:
    server = AstraWebServer(host=host, port=port)
    actual_port = server.start(daemon=daemon)
    return server, actual_port
