"""Session Management CLI Commands."""

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from astrarecon.cli.ui.theme import COLOR_ACCENT, COLOR_DIVIDER, COLOR_ERROR, COLOR_SUCCESS, COLOR_WARNING, PANEL_BOX
from astrarecon.core.models.session import SessionStatus
from astrarecon.core.sessions.manager import SessionManager

app = typer.Typer(help="Manage and inspect persistent scan sessions.")
console = Console()


def get_sessions_dir() -> Path:
    return SessionManager().base_dir


@app.command("list")
def list_sessions():
    """List all recorded reconnaissance sessions."""
    sessions_dir = get_sessions_dir()
    if not sessions_dir.exists():
        console.print("[yellow]No sessions found. Run 'astrarecon scan <target>' to create one.[/yellow]")
        return

    session_folders = sorted(
        [d for d in sessions_dir.iterdir() if d.is_dir() and (d / "session.json").exists()],
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    )

    if not session_folders:
        console.print("[yellow]No sessions found in ~/.astrarecon/sessions/.[/yellow]")
        return

    table = Table(title="Recorded Scan Sessions", show_header=True, header_style="bold cyan")
    table.add_column("Session ID", width=28)
    table.add_column("Target", width=22)
    table.add_column("Status", width=14)
    table.add_column("Progress", width=10)
    table.add_column("Created At")

    for folder in session_folders:
        try:
            with open(folder / "session.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            status = data.get("status", "UNKNOWN")
            status_style = {
                "COMPLETED": "green",
                "RUNNING": "blue",
                "INTERRUPTED": "yellow",
                "PAUSED_LOW_DISK": "red",
                "FAILED": "red",
            }.get(status, "white")

            progress = f"{data.get('progress_percentage', 0.0):.0f}%"
            table.add_row(
                data.get("session_id", folder.name),
                data.get("target", "N/A"),
                f"[{status_style}]{status}[/{status_style}]",
                progress,
                str(data.get("created_at", "N/A"))[:19],
            )
        except Exception:
            continue

    console.print(table)


@app.command("inspect")
def inspect_session(session_id: str = typer.Argument(..., help="ID of session to inspect")):
    """Inspect detailed checkpoint state and diagnostics for a specific session."""
    session_dir = get_sessions_dir() / session_id
    session_file = session_dir / "session.json"

    if not session_file.exists():
        console.print(f"[bold red]Error:[/bold red] Session '{session_id}' not found in {get_sessions_dir()}.")
        raise typer.Exit(code=1)

    with open(session_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    status = data.get("status", "UNKNOWN")
    target = data.get("target", "unknown")

    status_color = "green" if status == "COMPLETED" else "yellow" if status == "INTERRUPTED" else "red" if status == "FAILED" else "cyan"

    console.print(f"\n[bold cyan]Session Details:[/bold cyan] [bold white]{session_id}[/bold white]")
    console.print(f"Target:      [bold]{target}[/bold]")
    console.print(f"Status:      [{status_color}]{status}[/{status_color}]")
    console.print(f"Progress:    {data.get('progress_percentage', 0.0):.1f}%")
    console.print(f"Created:     {data.get('created_at')}")

    # Inspect checkpoints
    checkpoints_dir = session_dir / "checkpoints"
    failed_checkpoints = []

    if checkpoints_dir.exists():
        cp_files = sorted(checkpoints_dir.glob("*.json"))
        if cp_files:
            table = Table(title="Pipeline Checkpoints", show_header=True, header_style="bold magenta")
            table.add_column("Node ID", width=18)
            table.add_column("Plugin / Type", width=16)
            table.add_column("Status", width=12)
            table.add_column("Duration", width=10)
            table.add_column("Outputs", width=12)
            table.add_column("Cache Hit", width=10)

            for cp in cp_files:
                try:
                    with open(cp, "r", encoding="utf-8") as f:
                        cp_data = json.load(f)
                    dur = f"{cp_data.get('duration_seconds', 0.0):.1f}s"
                    st = cp_data.get("status", "N/A")
                    st_style = "green" if st == "COMPLETED" else "red" if st == "FAILED" else "yellow"

                    outputs = cp_data.get("outputs", {})
                    out_count = sum(v.get("line_count", 0) for v in outputs.values() if isinstance(v, dict)) if outputs else 0
                    out_str = f"{out_count} items" if out_count > 0 else "--"

                    table.add_row(
                        cp_data.get("node_id", cp.stem),
                        cp_data.get("plugin_id", "N/A"),
                        f"[{st_style}]{st}[/{st_style}]",
                        dur,
                        out_str,
                        "Yes" if cp_data.get("cache_hit") else "No",
                    )

                    if st == "FAILED":
                        failed_checkpoints.append(cp_data)
                except Exception:
                    continue

            console.print()
            console.print(table)

    # Detailed diagnostics for failed nodes
    if failed_checkpoints:
        console.print("\n[bold red]Failures & Error Diagnostics:[/bold red]")
        for f_cp in failed_checkpoints:
            node_name = f_cp.get("node_id", "unknown")
            err_msg = f_cp.get("error_message", "Unknown error")
            stderr_path = session_dir / "logs" / f"{node_name}.stderr.log"

            err_details = [f"[bold]{node_name}:[/bold] {err_msg}"]
            if stderr_path.exists():
                err_details.append(f"[dim]Log file: {stderr_path}[/dim]")

            console.print(
                Panel(
                    "\n".join(err_details),
                    title=f"[red]Node Failure: {node_name}[/red]",
                    border_style="red",
                    box=PANEL_BOX,
                )
            )

    # Actionable guidance
    if status in ("INTERRUPTED", "FAILED"):
        console.print(
            f"\n[bold cyan]To resume this session, run:[/bold cyan] "
            f"[bold green]astrarecon scan {target} --resume {session_id}[/bold green]\n"
        )
    else:
        console.print()


@app.command("delete")
def delete_session(
    session_id: str = typer.Argument(..., help="ID of session to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Force deletion without confirmation prompt"),
):
    """Delete a specific reconnaissance session and reclaim disk space."""
    mgr = SessionManager()
    session_dir = mgr.base_dir / session_id

    if not session_dir.exists():
        console.print(f"[bold red]Error:[/bold red] Session '{session_id}' not found.")
        raise typer.Exit(code=1)

    if not force:
        confirmed = typer.confirm(f"Are you sure you want to permanently delete session '{session_id}'?")
        if not confirmed:
            console.print("[dim]Deletion cancelled.[/dim]")
            return

    success = mgr.delete_session(session_id)
    if success:
        console.print(f"[bold green]✔[/bold green] Session '{session_id}' successfully deleted.")
    else:
        console.print(f"[bold red]Error:[/bold red] Failed to delete session '{session_id}'.")


@app.command("prune")
def prune_sessions(
    days: int = typer.Option(7, "--days", "-d", help="Delete sessions older than N days"),
    failed_only: bool = typer.Option(False, "--failed-only", help="Delete all failed or interrupted sessions"),
    force: bool = typer.Option(False, "--force", "-f", help="Force deletion without confirmation prompt"),
):
    """Prune old or stale reconnaissance sessions to free disk space."""
    mgr = SessionManager()
    status_filter = [SessionStatus.FAILED, SessionStatus.INTERRUPTED] if failed_only else None

    if not force:
        target_desc = "failed/interrupted sessions" if failed_only else f"sessions older than {days} day(s)"
        confirmed = typer.confirm(f"Prune all {target_desc} from ~/.astrarecon/sessions/?")
        if not confirmed:
            console.print("[dim]Pruning cancelled.[/dim]")
            return

    count, reclaimed = mgr.prune_sessions(older_than_days=days, status_filter=status_filter)
    mb = reclaimed / (1024 * 1024)
    if count > 0:
        console.print(f"[bold green]✔[/bold green] Pruned {count} session(s), reclaimed [bold cyan]{mb:.1f} MB[/bold cyan] of disk space.")
    else:
        console.print("[dim]No matching sessions found to prune.[/dim]")
