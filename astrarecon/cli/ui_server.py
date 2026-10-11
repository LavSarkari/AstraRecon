"""Visual Web Canvas & Dashboard CLI Command."""

from __future__ import annotations

import os
import sys
import webbrowser
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from astrarecon import __version__
from astrarecon.cli.ui.theme import COLOR_ACCENT, COLOR_PRIMARY, COLOR_SUCCESS, COLOR_WARNING, PANEL_BOX
from astrarecon.web.server import start_web_server

app = typer.Typer(
    help="Launch the lightweight visual DAG canvas & web dashboard.",
    invoke_without_command=True,
)
console = Console(legacy_windows=False)


@app.callback()
def run_ui(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host address (use 0.0.0.0 for VPS remote access)."),
    port: int = typer.Option(8080, "--port", "-p", help="Bind port number (defaults to 8080)."),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not automatically open the web browser upon start."),
):
    """Launches the AstraRecon visual web canvas and real-time mission dashboard."""
    # Detect headless / SSH environment
    is_headless = bool(os.environ.get("SSH_CLIENT") or os.environ.get("SSH_TTY") or not sys.stdin.isatty())
    should_open_browser = not no_browser and not is_headless

    try:
        server, actual_port = start_web_server(host=host, port=port, daemon=True)
    except Exception as e:
        console.print(f"[bold red][-] Failed to start AstraRecon web server:[/bold red] {e}")
        raise typer.Exit(code=1)

    url = f"http://{'localhost' if host in ('127.0.0.1', '0.0.0.0') else host}:{actual_port}"

    panel_content = Text()
    panel_content.append("✦ ", style=f"bold {COLOR_ACCENT}")
    panel_content.append("AstraRecon Visual Canvas & Real-time Web Dashboard\n\n", style=f"bold {COLOR_PRIMARY}")
    panel_content.append("  • URL:               ", style="dim")
    panel_content.append(f"{url}\n", style=f"bold {COLOR_SUCCESS}")
    panel_content.append("  • Architecture:      ", style="dim")
    panel_content.append("Zero-overhead stdlib HTTP & Server-Sent Events\n", style=f"{COLOR_ACCENT}")
    panel_content.append("  • Memory Footprint:  ", style="dim")
    panel_content.append("< 20 MB RAM (VPS & Cloud Optimized)\n\n", style="dim white")
    panel_content.append("Press ", style="dim")
    panel_content.append("Ctrl+C", style=f"bold {COLOR_WARNING}")
    panel_content.append(" anytime in terminal to gracefully stop the web server.", style="dim")

    console.print("")
    console.print(
        Panel(
            panel_content,
            title=f"[bold {COLOR_PRIMARY}] ASTRA[/bold {COLOR_PRIMARY}][bold {COLOR_ACCENT}]RECON[/bold {COLOR_ACCENT}] [dim]• v{__version__}[/dim]",
            border_style=COLOR_PRIMARY,
            box=PANEL_BOX,
            padding=(1, 2),
        )
    )

    if should_open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        # Keep main thread alive until user interrupts
        server.server.serve_forever()
    except KeyboardInterrupt:
        console.print(f"\n[bold {COLOR_WARNING}][!] Shutting down AstraRecon web server...[/bold {COLOR_WARNING}]")
        server.stop()
        console.print(f"[dim]Web server successfully stopped.[/dim]\n")
        raise typer.Exit(code=0)
