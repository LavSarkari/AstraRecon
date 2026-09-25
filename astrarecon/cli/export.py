"""Export CLI: Render or re-generate export bundles from completed sessions."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from astrarecon.cli.ui.theme import COLOR_ACCENT, COLOR_DIVIDER, COLOR_ERROR, COLOR_SUCCESS, COLOR_WARNING, PANEL_BOX
from astrarecon.core.reports.ai_export import AIDistillationEngine
from astrarecon.core.reports.output_writer import OutputFormat, OutputWriter
from astrarecon.core.reports.result_renderer import ScanResultLoader, ScanResultsRenderer
from astrarecon.core.sessions.manager import SessionManager

app = typer.Typer(help="Export or view scan results from completed sessions.")
console = Console(legacy_windows=False)


def _resolve_session(session_id: str, session_mgr: SessionManager) -> Path:
    """Resolve session_id → session directory, with friendly error."""
    session_dir = session_mgr.base_dir / session_id
    if not session_dir.exists():
        console.print(f"\n[bold {COLOR_ERROR}]Error:[/bold {COLOR_ERROR}] Session '[bold]{session_id}[/bold]' not found.")
        console.print(f"[dim]Run [bold]astrarecon sessions list[/bold] to see available sessions.[/dim]\n")
        raise typer.Exit(code=1)
    return session_dir


@app.command("ai")
def export_ai(
    session_id: str = typer.Argument(..., help="Session ID to export (e.g. 2026-09-26-001-example-com)"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Custom output directory (default: <session>/exports/ai)"),
    show: bool = typer.Option(True, "--show/--no-show", help="Print bundle contents summary to terminal after export"),
):
    """Generate (or re-generate) the AI distillation bundle for a session.

    Produces: context.json, findings.json, js_manifest.json, prompt.md
    """
    session_mgr = SessionManager()
    session_dir = _resolve_session(session_id, session_mgr)
    snap = session_mgr.load_session_snapshot(session_dir)
    target = snap.target

    dest = output_dir or (session_dir / "exports")

    console.print(f"\n  [dim]Generating AI bundle for session [bold]{session_id}[/bold]…[/dim]")

    try:
        ai_dir = AIDistillationEngine.export_bundle(
            target=target,
            session_dir=session_dir,
            output_dir=dest,
        )
    except Exception as e:
        console.print(f"[bold {COLOR_ERROR}]Error generating AI bundle:[/bold {COLOR_ERROR}] {e}\n")
        raise typer.Exit(code=1)

    console.print(f"\n  [{COLOR_SUCCESS}]✔[/{COLOR_SUCCESS}] AI bundle written → [bold {COLOR_ACCENT}]{ai_dir}[/bold {COLOR_ACCENT}]\n")

    if show:
        # Show what was generated
        files = list(ai_dir.glob("*"))
        tbl = Table(show_header=True, header_style=f"bold {COLOR_ACCENT}", box=None, padding=(0, 2))
        tbl.add_column("File", style=f"bold {COLOR_ACCENT}")
        tbl.add_column("Size", style="dim", justify="right")
        tbl.add_column("Description")
        _file_desc = {
            "context.json":    "Target scope, CIDR ranges, live endpoints, and environment fingerprint",
            "findings.json":   "Triaged vulnerabilities by severity with reproducible curl commands",
            "js_manifest.json":"Extracted endpoints, API routes, and tokens from JavaScript files",
            "prompt.md":       "Pre-populated LLM system prompt with distilled attack surface data",
        }
        for f in sorted(files):
            size = f"{f.stat().st_size // 1024 + 1} KB" if f.exists() else "—"
            tbl.add_row(f.name, size, _file_desc.get(f.name, ""))

        panel = Panel(
            tbl,
            title=f"[bold {COLOR_SUCCESS}]✔ AI Export Bundle — {target}[/bold {COLOR_SUCCESS}]",
            title_align="left",
            box=PANEL_BOX,
            border_style=COLOR_DIVIDER,
            padding=(0, 1),
        )
        console.print(panel)
        console.print(
            f"\n  [dim]Feed [bold]context.json[/bold] + [bold]prompt.md[/bold] to GPT-4o, Claude, or Gemini "
            f"for instant LLM triage.[/dim]\n"
        )


@app.command("results")
def export_results(
    session_id: str = typer.Argument(..., help="Session ID to view"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save results to file (.json, .md, .csv)"),
    output_format: Optional[str] = typer.Option(None, "--output-format", help="Force format: json | md | csv"),
    no_results: bool = typer.Option(False, "--no-results", help="Skip the pretty tables, show summary only"),
):
    """Show results from any completed session in the terminal.

    Examples:

        astrarecon export results 2026-09-26-001-example-com

        astrarecon export results 2026-09-26-001-example-com --output report.md
    """
    session_mgr = SessionManager()
    session_dir = _resolve_session(session_id, session_mgr)
    snap = session_mgr.load_session_snapshot(session_dir)
    target = snap.target

    scan_results = ScanResultLoader.load(session_dir=session_dir, target=target)

    console.print()
    console.print(Rule(
        title=f"[bold {COLOR_ACCENT}]  SESSION RESULTS — {session_id}  [/bold {COLOR_ACCENT}]",
        style=COLOR_DIVIDER,
    ))

    if not no_results:
        ScanResultsRenderer.render_all(scan_results, limit=True)

    if output:
        fmt: OutputFormat | None = None
        if output_format:
            try:
                fmt = OutputFormat(output_format.lower().lstrip("."))
            except ValueError:
                console.print(
                    f"[bold {COLOR_ERROR}]Error:[/bold {COLOR_ERROR}] Unknown format "
                    f"'[bold]{output_format}[/bold]'. Valid: json, md, csv\n"
                )
                raise typer.Exit(code=1)

        try:
            written_path = OutputWriter.write(scan_results, output, fmt)
            console.print(
                f"  [{COLOR_SUCCESS}]✔[/{COLOR_SUCCESS}] Results saved → "
                f"[bold {COLOR_ACCENT}]{written_path}[/bold {COLOR_ACCENT}]  "
                f"[dim]({scan_results.subdomain_count} subdomains · "
                f"{scan_results.live_host_count} hosts · "
                f"{scan_results.finding_count} findings)[/dim]\n"
            )
        except Exception as e:
            console.print(f"[bold {COLOR_ERROR}]Error writing output:[/bold {COLOR_ERROR}] {e}\n")
            raise typer.Exit(code=1)
