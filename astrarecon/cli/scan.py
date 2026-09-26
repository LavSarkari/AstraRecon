"""Scan CLI Command: Launch or Resume Reconnaissance Workflows."""

import asyncio
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from astrarecon.cli.ui.components import CompletionSummaryView, StatusPanel
from astrarecon.cli.ui.theme import COLOR_ACCENT, COLOR_DIVIDER, COLOR_ERROR, COLOR_SECONDARY, COLOR_SUCCESS, COLOR_WARNING, PANEL_BOX
from astrarecon.core.cache.cas import ContentAddressedStore
from astrarecon.core.doctor.inspector import EnvironmentInspector
from astrarecon.core.execution.runner import ExecutionEngine
from astrarecon.core.models.session import EnvFingerprint, NodeExecutionStatus, SessionStatus
from astrarecon.core.models.workflow import EdgeDefinition, NodeDefinition, WorkflowDefinition, WorkflowScope
from astrarecon.core.plugins.loader import PluginLoader
from astrarecon.core.reports.ai_export import AIDistillationEngine
from astrarecon.core.reports.output_writer import OutputFormat, OutputWriter
from astrarecon.core.reports.result_renderer import ScanResultLoader, ScanResultsRenderer
from astrarecon.core.sessions.manager import SessionManager
from astrarecon.core.validation import check_disk_space, validate_target

app = typer.Typer(
    help="Execute or resume reconnaissance workflows.",
    context_settings={"allow_interspersed_args": True},
)
console = Console(legacy_windows=False)


def _show_completed_session_results(
    session_dir: "Path",
    snapshot: "any",
    target: str,
    session_mgr: "SessionManager",
    con: "Console",
) -> None:
    """Renders results for an already-completed session without re-running the engine."""
    from astrarecon.cli.ui.components import CompletionSummaryView
    from astrarecon.core.reports.result_renderer import ScanResultLoader, ScanResultsRenderer

    scan_results = ScanResultLoader.load(session_dir=session_dir, target=target)

    # Fallback counts from checkpoints if artifact files not yet present
    total_subdomains = scan_results.subdomain_count
    live_hosts = scan_results.live_host_count
    total_vulns = scan_results.finding_count

    if total_subdomains == 0 and live_hosts == 0:
        checkpoints = session_mgr.load_checkpoints(session_dir)
        for cp in checkpoints.values():
            for port_name, ref in (cp.outputs or {}).items():
                p = Path(ref.path)
                if not p.is_file():
                    continue
                try:
                    count = sum(1 for l in p.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip())
                except Exception:
                    count = 0
                ref_type = str(ref.type).lower()
                if "domain" in ref_type:
                    total_subdomains = max(total_subdomains, count)
                elif "host" in ref_type or "url" in ref_type:
                    live_hosts = max(live_hosts, count)
                elif "vuln" in ref_type:
                    total_vulns += count

    ai_dir = session_dir / "exports" / "ai"

    summary = CompletionSummaryView.render(
        target=target,
        duration_seconds=0,
        session_id=session_dir.name,
        total_subdomains=total_subdomains,
        live_hosts=live_hosts,
        vulnerabilities=total_vulns,
        ai_bundle_path=str(ai_dir) if ai_dir.exists() else None,
    )
    con.print("")
    con.print(summary)
    ScanResultsRenderer.render_all(scan_results, limit=True)


def build_workflow(
    target: str,
    preset: str = "default",
    scope_include: Optional[str] = None,
    scope_exclude: Optional[str] = None,
    with_tools: Optional[list[str]] = None,
    skip_tools: Optional[list[str]] = None,
    custom_tools: Optional[list[str]] = None,
) -> WorkflowDefinition:
    """Builds a comprehensive or preset-specific WorkflowDefinition DAG with dynamic tool injection."""
    preset = (preset or "default").lower().strip()
    scope = WorkflowScope(
        auto_enforce_root=True,
        include_patterns=[scope_include] if scope_include else [],
        exclude_patterns=[scope_exclude] if scope_exclude else [],
    )
    plugin_registry = PluginLoader.load_all_plugins()

    if custom_tools:
        # Dynamic customized workflow with only specified tools
        nodes = [
            NodeDefinition(id="target_input", type="builtin.target_input", config={"raw_input": target}),
            NodeDefinition(id="scope_guard", type="builtin.scope_guard", config={}),
        ]
        edges = [
            EdgeDefinition(source="target_input", source_port="output", target="scope_guard", target_port="input"),
        ]

        sub_tools = []
        dns_tools = []
        port_tools = []
        live_tools = []
        crawl_tools = []
        vuln_tools = []
        other_tools = []

        for t_name in custom_tools:
            manifest = plugin_registry.get(t_name)
            stage = manifest.stage.lower() if manifest else "custom"
            if stage == "subdomains":
                sub_tools.append(t_name)
            elif stage == "dns":
                dns_tools.append(t_name)
            elif stage == "ports":
                port_tools.append(t_name)
            elif stage in ("live_hosts", "probing"):
                live_tools.append(t_name)
            elif stage in ("crawling", "urls"):
                crawl_tools.append(t_name)
            elif stage in ("vulns", "xss"):
                vuln_tools.append(t_name)
            else:
                other_tools.append(t_name)

        # Wire subdomain tools
        sub_outputs = []
        for st in sub_tools:
            m = plugin_registry.get(st)
            in_port = m.inputs[0].name if m and m.inputs else "target"
            out_port = m.outputs[0].name if m and m.outputs else "subdomains"
            nodes.append(NodeDefinition(id=st, type=f"plugin.{st}", config={}))
            edges.append(EdgeDefinition(source="scope_guard", source_port="in_scope", target=st, target_port=in_port))
            sub_outputs.append((st, out_port))

        last_domain_source = "scope_guard"
        last_domain_port = "in_scope"

        if len(sub_outputs) > 1:
            nodes.append(NodeDefinition(id="union_dedupe", type="builtin.union_dedupe", config={}))
            for src_id, src_p in sub_outputs:
                edges.append(EdgeDefinition(source=src_id, source_port=src_p, target="union_dedupe", target_port="inputs"))
            last_domain_source = "union_dedupe"
            last_domain_port = "output"
        elif len(sub_outputs) == 1:
            last_domain_source = sub_outputs[0][0]
            last_domain_port = sub_outputs[0][1]

        # Wire DNS tools
        last_host_source = last_domain_source
        last_host_port = last_domain_port
        for dt in dns_tools:
            m = plugin_registry.get(dt)
            in_port = m.inputs[0].name if m and m.inputs else "hosts"
            out_port = m.outputs[0].name if m and m.outputs else "valid_hosts"
            nodes.append(NodeDefinition(id=dt, type=f"plugin.{dt}", config={}))
            edges.append(EdgeDefinition(source=last_domain_source, source_port=last_domain_port, target=dt, target_port=in_port))
            last_host_source = dt
            last_host_port = out_port

        # Wire Port scanning tools
        for pt in port_tools:
            m = plugin_registry.get(pt)
            in_port = m.inputs[0].name if m and m.inputs else "hosts"
            nodes.append(NodeDefinition(id=pt, type=f"plugin.{pt}", config={}))
            edges.append(EdgeDefinition(source=last_host_source, source_port=last_host_port, target=pt, target_port=in_port))

        # Wire Live host probing tools
        last_endpoint_source = None
        last_endpoint_port = None
        for lt in live_tools:
            m = plugin_registry.get(lt)
            in_port = m.inputs[0].name if m and m.inputs else "targets"
            out_port = m.outputs[0].name if m and m.outputs else "endpoints"
            nodes.append(NodeDefinition(id=lt, type=f"plugin.{lt}", config={}))
            edges.append(EdgeDefinition(source=last_host_source, source_port=last_host_port, target=lt, target_port=in_port))
            last_endpoint_source = lt
            last_endpoint_port = out_port

        # Wire Crawling / URL tools
        for ct in crawl_tools:
            m = plugin_registry.get(ct)
            in_port = m.inputs[0].name if m and m.inputs else "endpoints"
            in_source = m.inputs[0].source if m and m.inputs else "artifact"
            nodes.append(NodeDefinition(id=ct, type=f"plugin.{ct}", config={}))
            if in_source == "param":
                edges.append(EdgeDefinition(source="scope_guard", source_port="in_scope", target=ct, target_port=in_port))
            elif last_endpoint_source:
                edges.append(EdgeDefinition(source=last_endpoint_source, source_port=last_endpoint_port, target=ct, target_port=in_port))
            else:
                edges.append(EdgeDefinition(source=last_host_source, source_port=last_host_port, target=ct, target_port=in_port))

        # Wire Vulnerability scanning tools
        for vt in vuln_tools:
            m = plugin_registry.get(vt)
            in_port = m.inputs[0].name if m and m.inputs else "targets"
            nodes.append(NodeDefinition(id=vt, type=f"plugin.{vt}", config={}))
            if last_endpoint_source:
                edges.append(EdgeDefinition(source=last_endpoint_source, source_port=last_endpoint_port, target=vt, target_port=in_port))
            else:
                edges.append(EdgeDefinition(source=last_host_source, source_port=last_host_port, target=vt, target_port=in_port))

        # Wire any other custom tools
        for ot in other_tools:
            m = plugin_registry.get(ot)
            in_port = m.inputs[0].name if m and m.inputs else "input"
            in_source = m.inputs[0].source if m and m.inputs else "artifact"
            nodes.append(NodeDefinition(id=ot, type=f"plugin.{ot}", config={}))
            if in_source == "param":
                edges.append(EdgeDefinition(source="scope_guard", source_port="in_scope", target=ot, target_port=in_port))
            elif last_endpoint_source:
                edges.append(EdgeDefinition(source=last_endpoint_source, source_port=last_endpoint_port, target=ot, target_port=in_port))
            else:
                edges.append(EdgeDefinition(source=last_host_source, source_port=last_host_port, target=ot, target_port=in_port))

        wf_name = f"Custom scan ({','.join(custom_tools)}) for {target}"

    else:
        # Standard presets
        if preset == "fast":
            nodes = [
                NodeDefinition(id="target_input", type="builtin.target_input", config={"raw_input": target}),
                NodeDefinition(id="scope_guard", type="builtin.scope_guard", config={}),
                NodeDefinition(id="subfinder", type="plugin.subfinder", config={}),
                NodeDefinition(id="dnsx", type="plugin.dnsx", config={}),
                NodeDefinition(id="httpx", type="plugin.httpx", config={}),
            ]
            edges = [
                EdgeDefinition(source="target_input", source_port="output", target="scope_guard", target_port="input"),
                EdgeDefinition(source="scope_guard", source_port="in_scope", target="subfinder", target_port="target"),
                EdgeDefinition(source="subfinder", source_port="subdomains", target="dnsx", target_port="hosts"),
                EdgeDefinition(source="dnsx", source_port="valid_hosts", target="httpx", target_port="targets"),
            ]
            wf_name = f"Fast recon for {target}"

        elif preset == "passive":
            nodes = [
                NodeDefinition(id="target_input", type="builtin.target_input", config={"raw_input": target}),
                NodeDefinition(id="scope_guard", type="builtin.scope_guard", config={}),
                NodeDefinition(id="subfinder", type="plugin.subfinder", config={}),
                NodeDefinition(id="assetfinder", type="plugin.assetfinder", config={}),
                NodeDefinition(id="amass", type="plugin.amass", config={}),
                NodeDefinition(id="union_dedupe", type="builtin.union_dedupe", config={}),
                NodeDefinition(id="gau", type="plugin.gau", config={}),
            ]
            edges = [
                EdgeDefinition(source="target_input", source_port="output", target="scope_guard", target_port="input"),
                EdgeDefinition(source="scope_guard", source_port="in_scope", target="subfinder", target_port="target"),
                EdgeDefinition(source="scope_guard", source_port="in_scope", target="assetfinder", target_port="target"),
                EdgeDefinition(source="scope_guard", source_port="in_scope", target="amass", target_port="target"),
                EdgeDefinition(source="scope_guard", source_port="in_scope", target="gau", target_port="target"),
                EdgeDefinition(source="subfinder", source_port="subdomains", target="union_dedupe", target_port="inputs"),
                EdgeDefinition(source="assetfinder", source_port="subdomains", target="union_dedupe", target_port="inputs"),
                EdgeDefinition(source="amass", source_port="subdomains", target="union_dedupe", target_port="inputs"),
            ]
            wf_name = f"Passive recon for {target}"

        elif preset == "vuln":
            nodes = [
                NodeDefinition(id="target_input", type="builtin.target_input", config={"raw_input": target}),
                NodeDefinition(id="scope_guard", type="builtin.scope_guard", config={}),
                NodeDefinition(id="subfinder", type="plugin.subfinder", config={}),
                NodeDefinition(id="dnsx", type="plugin.dnsx", config={}),
                NodeDefinition(id="httpx", type="plugin.httpx", config={}),
                NodeDefinition(id="nuclei", type="plugin.nuclei", config={}),
            ]
            edges = [
                EdgeDefinition(source="target_input", source_port="output", target="scope_guard", target_port="input"),
                EdgeDefinition(source="scope_guard", source_port="in_scope", target="subfinder", target_port="target"),
                EdgeDefinition(source="subfinder", source_port="subdomains", target="dnsx", target_port="hosts"),
                EdgeDefinition(source="dnsx", source_port="valid_hosts", target="httpx", target_port="targets"),
                EdgeDefinition(source="httpx", source_port="endpoints", target="nuclei", target_port="targets"),
            ]
            wf_name = f"Vulnerability assessment for {target}"

        else:
            # Default / Full comprehensive reconnaissance & vulnerability pipeline
            nodes = [
                NodeDefinition(id="target_input", type="builtin.target_input", config={"raw_input": target}),
                NodeDefinition(id="scope_guard", type="builtin.scope_guard", config={}),
                NodeDefinition(id="subfinder", type="plugin.subfinder", config={}),
                NodeDefinition(id="assetfinder", type="plugin.assetfinder", config={}),
                NodeDefinition(id="amass", type="plugin.amass", config={}),
                NodeDefinition(id="union_dedupe", type="builtin.union_dedupe", config={}),
                NodeDefinition(id="dnsx", type="plugin.dnsx", config={}),
                NodeDefinition(id="naabu", type="plugin.naabu", config={}),
                NodeDefinition(id="httpx", type="plugin.httpx", config={}),
                NodeDefinition(id="gau", type="plugin.gau", config={}),
                NodeDefinition(id="katana", type="plugin.katana", config={}),
                NodeDefinition(id="nuclei", type="plugin.nuclei", config={}),
            ]
            edges = [
                EdgeDefinition(source="target_input", source_port="output", target="scope_guard", target_port="input"),
                EdgeDefinition(source="scope_guard", source_port="in_scope", target="subfinder", target_port="target"),
                EdgeDefinition(source="scope_guard", source_port="in_scope", target="assetfinder", target_port="target"),
                EdgeDefinition(source="scope_guard", source_port="in_scope", target="amass", target_port="target"),
                EdgeDefinition(source="subfinder", source_port="subdomains", target="union_dedupe", target_port="inputs"),
                EdgeDefinition(source="assetfinder", source_port="subdomains", target="union_dedupe", target_port="inputs"),
                EdgeDefinition(source="amass", source_port="subdomains", target="union_dedupe", target_port="inputs"),
                EdgeDefinition(source="union_dedupe", source_port="output", target="dnsx", target_port="hosts"),
                EdgeDefinition(source="dnsx", source_port="valid_hosts", target="naabu", target_port="hosts"),
                EdgeDefinition(source="dnsx", source_port="valid_hosts", target="httpx", target_port="targets"),
                EdgeDefinition(source="scope_guard", source_port="in_scope", target="gau", target_port="target"),
                EdgeDefinition(source="httpx", source_port="endpoints", target="katana", target_port="endpoints"),
                EdgeDefinition(source="httpx", source_port="endpoints", target="nuclei", target_port="targets"),
            ]
            wf_name = f"Full recon scan for {target}"

    # Handle dynamic tool additions (--with)
    if with_tools:
        for wt in with_tools:
            manifest = plugin_registry.get(wt)
            if not manifest:
                console.print(f"[bold yellow]Warning:[/bold yellow] Plugin '{wt}' not found in registry. Skipping.")
                continue

            stage = manifest.stage.lower()
            in_port = manifest.inputs[0].name if manifest.inputs else "target"
            out_port = manifest.outputs[0].name if manifest.outputs else "output"
            in_src = manifest.inputs[0].source if manifest.inputs else "artifact"

            if not any(n.id == wt for n in nodes):
                nodes.append(NodeDefinition(id=wt, type=f"plugin.{wt}", config={}))

            if stage == "subdomains":
                edges.append(EdgeDefinition(source="scope_guard", source_port="in_scope", target=wt, target_port=in_port))
                if any(n.id == "union_dedupe" for n in nodes):
                    edges.append(EdgeDefinition(source=wt, source_port=out_port, target="union_dedupe", target_port="inputs"))
            elif stage in ("ports", "dns"):
                src = "dnsx" if any(n.id == "dnsx" for n in nodes) else "union_dedupe"
                src_port = "valid_hosts" if src == "dnsx" else "output"
                edges.append(EdgeDefinition(source=src, source_port=src_port, target=wt, target_port=in_port))
            elif stage in ("crawling", "urls"):
                if in_src == "param":
                    edges.append(EdgeDefinition(source="scope_guard", source_port="in_scope", target=wt, target_port=in_port))
                elif any(n.id == "httpx" for n in nodes):
                    edges.append(EdgeDefinition(source="httpx", source_port="endpoints", target=wt, target_port=in_port))
            elif stage in ("vulns", "xss"):
                if any(n.id == "httpx" for n in nodes):
                    edges.append(EdgeDefinition(source="httpx", source_port="endpoints", target=wt, target_port=in_port))
            else:
                if any(n.id == "httpx" for n in nodes):
                    edges.append(EdgeDefinition(source="httpx", source_port="endpoints", target=wt, target_port=in_port))
                else:
                    edges.append(EdgeDefinition(source="scope_guard", source_port="in_scope", target=wt, target_port=in_port))

    # Handle dynamic tool skips (--skip)
    if skip_tools:
        skip_set = set(skip_tools)
        nodes = [n for n in nodes if n.id not in skip_set]
        edges = [e for e in edges if e.source not in skip_set and e.target not in skip_set]

    return WorkflowDefinition(
        id=f"scan-{target}",
        name=wf_name,
        scope=scope,
        nodes=nodes,
        edges=edges,
    )


@app.callback(invoke_without_command=True)
def run_scan(
    target: Optional[str] = typer.Argument(None, help="Target domain, URL, or CIDR (e.g. example.com)"),
    workflow: str = typer.Option("default", "--workflow", "-w", help="Workflow preset to execute"),
    profile: str = typer.Option("auto", "--profile", "-p", help="Execution profile: 'auto', 'safe', 'default', 'beast'"),
    diff_only: bool = typer.Option(False, "--diff-only", help="Continuous recon: scan only newly discovered attack surfaces"),
    resume: Optional[str] = typer.Option(None, "--resume", "-r", help="Session ID to resume"),
    fresh: bool = typer.Option(False, "--fresh", "-f", help="Force starting a fresh scan without checking/prompting for existing sessions"),
    scope_include: Optional[str] = typer.Option(None, "--scope-include", help="Regex pattern of in-scope domains"),
    scope_exclude: Optional[str] = typer.Option(None, "--scope-exclude", help="Regex pattern of out-of-scope domains to quarantine"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Upstream HTTP/SOCKS5 proxy (e.g. http://127.0.0.1:8080)"),
    header: Optional[list[str]] = typer.Option(None, "--header", "-H", help="Custom HTTP headers to inject into scanners"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save full results to file. Format auto-detected from extension: .json, .md, .csv"),
    output_format: Optional[str] = typer.Option(None, "--output-format", help="Force output format: json | md | csv"),
    no_results: bool = typer.Option(False, "--no-results", help="Skip the pretty results table — only show the summary card"),
    clear: bool = typer.Option(False, "--clear", help="Clear all existing sessions for this target before scanning"),
    with_tools: Optional[list[str]] = typer.Option(None, "--with", help="Include extra registered tool(s) in this scan (e.g. --with findomain --with dalfox)"),
    skip_tools: Optional[list[str]] = typer.Option(None, "--skip", help="Omit specific tool(s) from running (e.g. --skip amass --skip gau)"),
    tools: Optional[str] = typer.Option(None, "--tools", help="Comma-separated list of exact tools to run (e.g. --tools subfinder,httpx,nuclei)"),
):
    """Launch or resume an automated reconnaissance workflow."""
    if not target and not resume:
        console.print("\n[bold red]Error:[/bold red] Target domain or --resume <session_id> is required.")
        console.print("[dim]Usage: astrarecon scan example.com[/dim]\n")
        raise typer.Exit(code=1)

    # Validate target domain / IP syntax if launching a scan
    if target:
        is_valid, norm_target, err_reason = validate_target(target)
        if not is_valid:
            console.print(f"\n[bold red]Error: Invalid target domain or IP specification:[/bold red] {err_reason}")
            console.print(
                "[dim]Supported formats include:\n"
                "  • FQDN / Domain:   example.com, api.target.io\n"
                "  • Wildcard Domain: *.example.com\n"
                "  • URL:             https://target.com\n"
                "  • IPv4 / CIDR:     192.168.1.1, 10.0.0.0/24[/dim]\n"
            )
            raise typer.Exit(code=1)
        target = norm_target

    # Validate upstream proxy format if provided
    if proxy and not any(proxy.startswith(p) for p in ("http://", "https://", "socks5://", "socks4://")):
        console.print(f"\n[bold red]Error: Invalid proxy format '{proxy}'.[/bold red]")
        console.print("[dim]Example: --proxy http://127.0.0.1:8080 or --proxy socks5://127.0.0.1:9050[/dim]\n")
        raise typer.Exit(code=1)

    session_mgr = SessionManager()

    # Low disk space guard (protect against out-of-disk failures during large recon scans)
    has_space, free_mb = check_disk_space(session_mgr.base_dir, min_mb=200.0)
    if not has_space:
        console.print(f"\n[bold red]Error: Insufficient disk space ({free_mb:.1f} MB remaining).[/bold red]")
        console.print(f"[yellow]AstraRecon requires at least 200 MB free space in '{session_mgr.base_dir}'.[/yellow]")
        console.print("[dim]Tip: Prune old scan sessions using 'astrarecon sessions prune'.[/dim]\n")
        raise typer.Exit(code=1)

    cas = ContentAddressedStore()
    plugin_registry = PluginLoader.load_all_plugins()
    env = EnvironmentInspector.inspect()

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

    # If --clear was explicitly passed, delete previous sessions for this target before scanning
    if target and clear:
        c_count, c_bytes = session_mgr.clear_sessions(target=target)
        c_mb = c_bytes / (1024 * 1024)
        if c_count > 0:
            console.print(f"[bold green]✔[/bold green] Cleared {c_count} previous session(s) for target '{target}' ({c_mb:.1f} MB reclaimed).\n")

    # Check for existing sessions on the same target domain when neither --resume nor --fresh nor --clear was passed
    if target and not resume and not fresh and not clear:
        existing_sessions = session_mgr.get_sessions_for_target(target)
        if existing_sessions:
            table = Table(
                show_header=True,
                header_style="bold #1DA1FF",
                box=None,
                padding=(0, 2),
            )
            table.add_column("#", style="bold cyan", width=4)
            table.add_column("Session ID", style="bold white", width=34)
            table.add_column("Age", style="dim", width=12)
            table.add_column("Status", width=16)
            table.add_column("Progress", style="dim", width=18)

            for idx, (s_dir, snap) in enumerate(existing_sessions[:5], start=1):
                delta_sec = time.time() - s_dir.stat().st_mtime
                if delta_sec < 60:
                    age = "just now"
                elif delta_sec < 3600:
                    age = f"{int(delta_sec // 60)}m ago"
                elif delta_sec < 86400:
                    age = f"{int(delta_sec // 3600)}h ago"
                else:
                    age = f"{int(delta_sec // 86400)}d ago"

                cps = session_mgr.load_checkpoints(s_dir)
                completed_cps = sum(1 for c in cps.values() if c.status == NodeExecutionStatus.COMPLETED)
                total_cps = len(cps) or 7
                stages_str = f"{completed_cps}/{total_cps} stages done"

                if snap.status == SessionStatus.COMPLETED:
                    status_style = "[green]● Completed[/green]"
                elif snap.status == SessionStatus.RUNNING:
                    status_style = "[yellow]● In Progress[/yellow]"
                elif snap.status == SessionStatus.FAILED:
                    status_style = "[red]● Failed[/red]"
                elif snap.status == SessionStatus.INTERRUPTED:
                    status_style = "[yellow]● Interrupted[/yellow]"
                else:
                    status_style = f"[dim]● {snap.status.value.capitalize()}[/dim]"

                table.add_row(Text(f"[{idx}]", style="bold #1DA1FF"), s_dir.name, age, status_style, stages_str)

            # Check whether the latest session is truly completed (all stages done)
            latest_dir, latest_snap = existing_sessions[0]
            latest_cps = session_mgr.load_checkpoints(latest_dir)
            latest_completed = sum(1 for c in latest_cps.values() if c.status == NodeExecutionStatus.COMPLETED)
            latest_total = max(len(latest_cps), 7)
            latest_is_done = (latest_snap.status == SessionStatus.COMPLETED) and (latest_completed >= latest_total)

            menu_text = Text()
            menu_text.append("\n  Actions:\n", style="bold white")
            if latest_is_done:
                menu_text.append("  [v] ", style="bold #22C55E")
                menu_text.append(f"View results for latest session ({latest_dir.name})\n", style="white")
                menu_text.append("  [r] ", style="bold #1DA1FF")
                menu_text.append(f"Resume / re-run latest session ({latest_dir.name})\n", style="white")
            else:
                menu_text.append("  [r] ", style="bold #1DA1FF")
                menu_text.append(f"Resume latest session ({latest_dir.name})\n", style="white")
                menu_text.append("  [v] ", style="bold #22C55E")
                menu_text.append(f"View results collected so far ({latest_dir.name})\n", style="white")
            menu_text.append("  [f] ", style="bold #1DA1FF")
            menu_text.append("Start a fresh scan (create new session)\n", style="white")
            menu_text.append("  [c] ", style="bold #EF4444")
            menu_text.append(f"Clear all existing sessions for '{target}' and start fresh\n", style="white")
            if len(existing_sessions) > 1:
                menu_text.append(f"  [1-{len(existing_sessions[:5])}] ", style="bold #1DA1FF")
                menu_text.append("Select a specific session from the list above\n", style="white")
            menu_text.append("  [q] ", style="bold #1DA1FF")
            menu_text.append("Cancel and exit\n", style="white")

            default_action = "v" if latest_is_done else "r"
            prompt_hint = "v=view results, r=resume, f=fresh, c=clear" if latest_is_done else "r=resume, v=view results, f=fresh, c=clear"
            if len(existing_sessions) > 1:
                prompt_hint += ", 1-N=select"
            prompt_hint += ", q=quit"

            panel = Panel(
                Group(
                    Text(f"Found {len(existing_sessions)} existing recon session(s) for target '{target}':\n", style="bold white"),
                    table,
                    menu_text,
                ),
                title="[bold white]ASTRA[/bold white][bold #1DA1FF]RECON[/bold #1DA1FF] [dim]─ Existing Sessions Detected[/dim]",
                title_align="left",
                box=PANEL_BOX,
                border_style=COLOR_DIVIDER,
                padding=(1, 2),
            )
            console.print(panel)

            if sys.stdin.isatty():
                try:
                    choice = Prompt.ask(
                        f"[bold #1DA1FF]Select action[/bold #1DA1FF] [{prompt_hint}]",
                        default=default_action,
                        console=console,
                    ).strip().lower()

                    if choice in ("q", "quit", "exit"):
                        console.print("[dim]Scan cancelled by user.[/dim]")
                        raise typer.Exit(code=0)
                    elif choice in ("c", "clear"):
                        c_count, c_bytes = session_mgr.clear_sessions(target=target)
                        c_mb = c_bytes / (1024 * 1024)
                        console.print(f"[bold green]✔[/bold green] Cleared {c_count} session(s) for '{target}' ({c_mb:.1f} MB reclaimed).\n")
                        resume = None  # Will create a fresh session below
                    elif choice in ("f", "fresh", "new"):
                        resume = None  # Will create a fresh session below
                    elif choice.isdigit() and 1 <= int(choice) <= len(existing_sessions[:5]):
                        chosen_dir, chosen_snap = existing_sessions[int(choice) - 1]
                        cps = session_mgr.load_checkpoints(chosen_dir)
                        c_cps = sum(1 for c in cps.values() if c.status == NodeExecutionStatus.COMPLETED)
                        if chosen_snap.status == SessionStatus.COMPLETED and c_cps >= max(len(cps), 7):
                            _show_completed_session_results(chosen_dir, chosen_snap, target, session_mgr, console)
                            raise typer.Exit(code=0)
                        else:
                            resume = chosen_dir.name
                    elif choice in ("v", "view"):
                        _show_completed_session_results(latest_dir, latest_snap, target, session_mgr, console)
                        raise typer.Exit(code=0)
                    elif choice in ("r", "resume"):
                        resume = latest_dir.name
                    else:
                        # Default: resume for incomplete, view results for completed
                        if latest_is_done:
                            _show_completed_session_results(latest_dir, latest_snap, target, session_mgr, console)
                            raise typer.Exit(code=0)
                        else:
                            resume = latest_dir.name
                except (KeyboardInterrupt, EOFError):
                    console.print("\n[dim]Scan cancelled by user.[/dim]")
                    raise typer.Exit(code=0)
            else:
                if latest_is_done:
                    console.print(f"[dim]Non-interactive mode: session {latest_dir.name} already completed. Use --fresh to start a new scan.[/dim]\n")
                    _show_completed_session_results(latest_dir, latest_snap, target, session_mgr, console)
                    raise typer.Exit(code=0)
                else:
                    resume = latest_dir.name
                    console.print(f"[dim]Non-interactive environment detected. Resuming session: {resume}[/dim]\n")

    if resume:
        session_dir = session_mgr.base_dir / resume
        if not session_dir.exists():
            console.print(f"[bold red]Error:[/bold red] Session '{resume}' not found.")
            raise typer.Exit(code=1)
        snapshot = session_mgr.load_session_snapshot(session_dir)
        target = snapshot.target
        with open(session_dir / "workflow.json", "r", encoding="utf-8") as f:
            wf = WorkflowDefinition.model_validate_json(f.read())
        is_resume = True
    else:
        custom_list = [t.strip().lower() for t in tools.split(",") if t.strip()] if tools else None
        wf = build_workflow(
            target=target,
            preset=workflow,
            scope_include=scope_include,
            scope_exclude=scope_exclude,
            with_tools=with_tools,
            skip_tools=skip_tools,
            custom_tools=custom_list,
        )
        session_dir = session_mgr.create_session(target=target, workflow=wf, fingerprint=fp)
        is_resume = False

    # Build dynamic node labels from registered plugins and engine nodes
    node_labels = {}
    for n in wf.nodes:
        if n.type.startswith("plugin."):
            p_id = n.type.split(".", 1)[1]
            manifest = plugin_registry.get(p_id)
            node_labels[n.id] = manifest.name if manifest else p_id.title()
        elif n.type.startswith("builtin."):
            b_name = n.type.split(".", 1)[1].replace("_", " ").title()
            node_labels[n.id] = b_name
        else:
            node_labels[n.id] = n.id.replace("_", " ").title()

    # Initialize Live Status Panel (compact, in-place, zero terminal spam)
    node_ids = [n.id for n in wf.nodes]
    status_panel = StatusPanel(
        target=target,
        node_ids=node_ids,
        workflow_id=wf.id,
        node_labels=node_labels,
    )


    start_time = time.time()

    with Live(status_panel.render(), console=console, refresh_per_second=10, transient=False) as live:
        def on_status_change(node_id: str, status, item_count=None, message=None):
            status_panel.update_status(node_id, status, item_count, message)
            live.update(status_panel.render())

        engine = ExecutionEngine(
            workflow=wf,
            session_dir=session_dir,
            plugin_registry=plugin_registry,
            cas=cas,
            session_manager=session_mgr,
            max_concurrent_workers=3,
            proxy=proxy,
            custom_headers=header,
            on_node_status_change=on_status_change,
        )

        async def _run_with_live_ticker():
            stop_event = asyncio.Event()

            async def _live_ticker():
                while not stop_event.is_set():
                    live.update(status_panel.render())
                    await asyncio.sleep(0.1)

            ticker_task = asyncio.create_task(_live_ticker())
            try:
                result = await engine.run(resume=is_resume)
                return result
            finally:
                stop_event.set()
                ticker_task.cancel()
                try:
                    await ticker_task
                except (asyncio.CancelledError, Exception):
                    pass
                live.update(status_panel.render())

        try:
            snapshot = asyncio.run(_run_with_live_ticker())
        except (KeyboardInterrupt, asyncio.CancelledError):
            live.update(status_panel.render())
            try:
                cur_snap = session_mgr.load_session_snapshot(session_dir)
                cur_snap.status = SessionStatus.INTERRUPTED
                session_mgr.save_session_snapshot(session_dir, cur_snap)
            except Exception:
                pass

            console.print(f"\n[bold yellow]Scan paused by user (Ctrl+C).[/bold yellow]")
            console.print(f"[dim]Session [bold white]{session_dir.name}[/bold white] state and checkpoints saved.[/dim]")
            console.print(f"[bold cyan]To resume anytime, run:[/bold cyan] astrarecon scan {target} --resume {session_dir.name}\n")
            raise typer.Exit(code=130)
        except Exception as e:
            live.update(status_panel.render())
            console.print(f"\n[bold red]Workflow execution error:[/bold red] {e}")
            console.print(f"[yellow]To resume execution, run: astrarecon scan {target} --resume {session_dir.name}[/yellow]\n")
            raise typer.Exit(code=1)

    # -----------------------------------------------------------------------
    # Load real scan results from artifact files
    # -----------------------------------------------------------------------
    scan_results = ScanResultLoader.load(session_dir=session_dir, target=target)

    # Count metrics from real data for the summary card
    total_subdomains = scan_results.subdomain_count
    live_hosts = scan_results.live_host_count
    total_vulns = scan_results.finding_count

    # Fallback: if artifacts dir is empty (e.g. dry run), count from checkpoints
    if total_subdomains == 0 and live_hosts == 0:
        checkpoints = session_mgr.load_checkpoints(session_dir)
        for cp in checkpoints.values():
            if cp.outputs:
                for port_name, ref in cp.outputs.items():
                    p = Path(ref.path)
                    if not p.is_file():
                        continue
                    try:
                        with open(p, "r", encoding="utf-8", errors="ignore") as _fp:
                            count = sum(1 for line in _fp if line.strip())
                    except Exception:
                        continue
                    ref_type = str(ref.type).lower()
                    if "domain" in ref_type:
                        total_subdomains = max(total_subdomains, count)
                    elif "host" in ref_type or "url" in ref_type:
                        live_hosts = max(live_hosts, count)
                    elif "vuln" in ref_type:
                        total_vulns += count

    # AI distillation export bundle
    ai_dir = None
    try:
        ai_dir = AIDistillationEngine.export_bundle(
            target=target,
            session_dir=session_dir,
            output_dir=session_dir / "exports",
        )
    except Exception:
        pass

    # -----------------------------------------------------------------------
    # Render Post-Scan Completion Summary card
    # -----------------------------------------------------------------------
    duration = time.time() - start_time
    summary_panel = CompletionSummaryView.render(
        target=target,
        duration_seconds=duration,
        session_id=session_dir.name,
        total_subdomains=total_subdomains,
        live_hosts=live_hosts,
        vulnerabilities=total_vulns,
        ai_bundle_path=str(ai_dir) if ai_dir else None,
    )
    console.print("")
    console.print(summary_panel)

    # -----------------------------------------------------------------------
    # Pretty Results Tables (subdomains, live hosts, findings)
    # -----------------------------------------------------------------------
    if not no_results:
        ScanResultsRenderer.render_all(scan_results, limit=True)

    # -----------------------------------------------------------------------
    # --output: write full results to file
    # -----------------------------------------------------------------------
    if output:
        fmt: OutputFormat | None = None
        if output_format:
            try:
                fmt = OutputFormat(output_format.lower().lstrip("."))
            except ValueError:
                console.print(
                    f"[bold {COLOR_ERROR}]Error:[/bold {COLOR_ERROR}] Unknown output format "
                    f"'[bold]{output_format}[/bold]'. Valid options: json, md, csv"
                )
                raise typer.Exit(code=1)

        try:
            written_path = OutputWriter.write(scan_results, output, fmt)
            console.print(
                f"  [{COLOR_SUCCESS}]✔[/{COLOR_SUCCESS}] Results saved → "
                f"[bold {COLOR_ACCENT}]{written_path}[/bold {COLOR_ACCENT}]  "
                f"[dim]({total_subdomains} subdomains · {live_hosts} hosts · {total_vulns} findings)[/dim]\n"
            )
        except Exception as e:
            console.print(f"[bold {COLOR_ERROR}]Error writing output file:[/bold {COLOR_ERROR}] {e}\n")
            raise typer.Exit(code=1)
