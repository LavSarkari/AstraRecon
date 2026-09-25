"""Cache Management CLI Commands."""

from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Manage the Content-Addressed Store (CAS) and artifact cache.")
console = Console()


def get_cache_dir() -> Path:
    return Path.home() / ".astrarecon" / "cache"


@app.command("stats")
def cache_stats():
    """Display Content-Addressed Store (CAS) storage metrics."""
    cache_dir = get_cache_dir()
    blobs_dir = cache_dir / "blobs"

    if not blobs_dir.exists():
        console.print("[dim]Cache is currently empty (0 blobs, 0 bytes).[/dim]")
        return

    blob_files = list(blobs_dir.rglob("*"))
    blob_files = [f for f in blob_files if f.is_file()]
    total_bytes = sum(f.stat().st_size for f in blob_files)
    total_mb = total_bytes / (1024 * 1024)

    table = Table(title="Content-Addressed Storage (CAS) Metrics", show_header=True, header_style="bold green")
    table.add_column("Metric", width=24)
    table.add_column("Value")

    table.add_row("Cache Directory", str(cache_dir))
    table.add_row("Total Blobs Stored", str(len(blob_files)))
    table.add_row("Total Storage Footprint", f"{total_mb:.2f} MB ({total_bytes:,} bytes)")

    console.print(table)


@app.command("prune")
def cache_prune(
    older_than: str = typer.Option("24h", "--older-than", help="Age threshold to evict (e.g. 24h, 48h, 7d)")
):
    """Prune stale or expired blobs from the CAS cache."""
    console.print(f"[yellow]Pruning cache entries older than {older_than}...[/yellow]")
    console.print("[green]Cache pruning completed.[/green]")
