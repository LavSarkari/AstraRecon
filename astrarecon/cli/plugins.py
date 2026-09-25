"""Plugin Management CLI Commands."""

import shutil
from pathlib import Path
import typer
from rich.box import ROUNDED
from rich.console import Console
from rich.table import Table

from astrarecon.cli.ui.theme import COLOR_ACCENT, COLOR_DIVIDER, COLOR_PRIMARY, COLOR_SECONDARY, COLOR_SUCCESS, COLOR_WARNING
from astrarecon.core.doctor.inspector import EnvironmentInspector
from astrarecon.core.plugins.loader import PluginLoader

app = typer.Typer(help="Manage and inspect security tool plugins.")
console = Console(legacy_windows=False)


@app.command("list")
def list_plugins():
    """List all installed security tool plugins."""
    table = Table(
        title="Registered Tool Plugins",
        show_header=True,
        header_style=f"bold {COLOR_ACCENT}",
        box=ROUNDED,
        border_style=COLOR_DIVIDER,
    )
    table.add_column("Plugin ID", style=f"bold {COLOR_PRIMARY}", width=14)
    table.add_column("Stage", style=f"{COLOR_SECONDARY}", width=12)
    table.add_column("Binary", style=f"bold {COLOR_PRIMARY}", width=13)
    table.add_column("Tool Version", style=f"{COLOR_ACCENT}", width=15)
    table.add_column("Plugin Rev", style="dim", width=12)
    table.add_column("Status", width=14)

    registry = PluginLoader.load_all_plugins()
    env = EnvironmentInspector.inspect()
    managed_bin = EnvironmentInspector.get_managed_bin_dir()

    manifests = sorted(registry.list_all(), key=lambda m: m.id)

    for m in manifests:
        bin_name = m.binary.name
        tool_status = env.tools.get(bin_name)
        is_installed = False
        detected_version = "[dim]--[/dim]"

        if tool_status and tool_status.installed:
            is_installed = True
            raw_ver = tool_status.version or "detected"
            detected_version = f"v{raw_ver}" if raw_ver[0].isdigit() else raw_ver
        elif shutil.which(bin_name):
            is_installed = True
            detected_version = "detected"
        elif (managed_bin / bin_name).is_file() or (managed_bin / f"{bin_name}.exe").is_file() or (managed_bin / f"{bin_name}.bat").is_file():
            is_installed = True
            detected_version = "detected"

        status_text = f"[{COLOR_SUCCESS}]✓ Installed[/{COLOR_SUCCESS}]" if is_installed else f"[{COLOR_WARNING}]✗ Missing[/{COLOR_WARNING}]"
        table.add_row(m.id, m.stage, bin_name, detected_version, f"v{m.plugin_version}", status_text)

    console.print(table)
