import sys
from typing import Optional
import typer
from rich.console import Console

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import os
from pathlib import Path

# Automatically ensure ~/.astrarecon/bin is in PATH for all subcommands and tool runners
managed_bin = Path.home() / ".astrarecon" / "bin"
if managed_bin.exists():
    bin_str = str(managed_bin)
    cur_path = os.environ.get("PATH", "")
    if bin_str not in cur_path:
        os.environ["PATH"] = f"{bin_str}{os.pathsep}{cur_path}"

from astrarecon import __version__
from astrarecon.cli.doctor import app as doctor_app
from astrarecon.cli.export import app as export_app
from astrarecon.cli.sessions import app as sessions_app
from astrarecon.cli.cache import app as cache_app
from astrarecon.cli.plugins import app as plugins_app
from astrarecon.cli.scan import app as scan_app
from astrarecon.cli.update import app as update_app
from astrarecon.cli.console import app as console_app

app = typer.Typer(
    name="astrarecon",
    help="Linux-first, DAG-based recon orchestration engine with persistent sessions.",
    no_args_is_help=False,
)
console = Console(legacy_windows=False)

# Register subcommands
app.add_typer(console_app, name="console")
app.add_typer(scan_app, name="scan")
app.add_typer(doctor_app, name="doctor")
app.add_typer(sessions_app, name="sessions")
app.add_typer(plugins_app, name="plugins")
app.add_typer(cache_app, name="cache")
app.add_typer(export_app, name="export")
app.add_typer(update_app, name="update")


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]AstraRecon[/bold cyan] version [bold green]{__version__}[/bold green]")
        raise typer.Exit()


def help_callback(ctx: typer.Context, value: bool):
    if value:
        from astrarecon.cli.ui.help import HelpMenuView
        console.print(HelpMenuView.render())
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Launch interactive reconnaissance console."
    ),
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True, help="Show version and exit."
    ),
    help: Optional[bool] = typer.Option(
        None, "--help", "-h", callback=help_callback, is_eager=True, help="Show enhanced command manual and options."
    ),
):
    """AstraRecon: Visual Recon Workflow Engine."""
    if ctx.invoked_subcommand is None:
        if interactive:
            from astrarecon.cli.console import run_console
            run_console()
            raise typer.Exit()
        from astrarecon.cli.ui.startup import StartupView
        console.print(StartupView.render())


def cli_entrypoint():
    try:
        from astrarecon.cli.update import check_and_prompt_update
        check_and_prompt_update()
    except Exception:
        pass

    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[dim]Operation cancelled by user.[/dim]")
        sys.exit(130)


if __name__ == "__main__":
    cli_entrypoint()
