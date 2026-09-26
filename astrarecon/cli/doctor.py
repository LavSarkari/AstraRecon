"""Doctor Command: System Diagnostics and Tool Availability."""

import sys
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from astrarecon.core.doctor.inspector import EnvironmentInspector
from astrarecon.core.doctor.installer import ToolInstaller

app = typer.Typer(help="Inspect host environment, dependencies, and tool binaries.")
console = Console()

# Cross-platform safe glyphs for non-UTF8 terminals
_encoding = (sys.stdout.encoding or "").lower()
USE_UNICODE = "utf" in _encoding
GLYPH_CHECK = "✓" if USE_UNICODE else "[OK]"
GLYPH_CROSS = "✗" if USE_UNICODE else "[X]"


@app.callback(invoke_without_command=True)
def run_doctor(
    install_missing: bool = typer.Option(
        False, "--install-missing", "-i", help="Automatically download missing tools to ~/.astrarecon/bin"
    )
):
    """Run full system health and security tool diagnostic check."""
    console.print("[bold cyan]AstraRecon Environment Doctor[/bold cyan]\n")

    from astrarecon.cli.ui.loader import AstraLoader

    with AstraLoader("Inspecting reconnaissance environment & tool binaries..."):
        env = EnvironmentInspector.inspect()

    # System table
    sys_table = Table(title="System & Runtimes", show_header=True, header_style="bold magenta")
    sys_table.add_column("Component", style="dim", width=22)
    sys_table.add_column("Status / Version")

    sys_table.add_row("Operating System", f"{env.os_name} ({env.os_version})")
    sys_table.add_row("Architecture / Kernel", f"{env.arch} / {env.kernel}")
    sys_table.add_row("Python Runtime", f"Python {env.python_version}")
    
    go_status = f"[green]{env.go_version}[/green]" if env.go_installed else "[yellow]Not Installed[/yellow]"
    sys_table.add_row("Go Compiler", go_status)

    managed_bin_status = (
        "[green]Found in PATH[/green]"
        if env.managed_bin_in_path
        else f"[yellow]Missing from PATH[/yellow] (Add: {EnvironmentInspector.get_managed_bin_dir()})"
    )
    sys_table.add_row("Managed Bin Directory", managed_bin_status)

    console.print(sys_table)
    console.print()

    # Tools table
    tool_table = Table(title="Security Tool Binaries", show_header=True, header_style="bold magenta")
    tool_table.add_column("Tool", width=16)
    tool_table.add_column("Status", width=12)
    tool_table.add_column("Version", width=16)
    tool_table.add_column("Binary Location")

    missing_tools: list[str] = []

    for name, status in env.tools.items():
        if status.installed:
            ver_text = status.version or "detected"
            tool_table.add_row(
                f"[bold]{name}[/bold]",
                f"[green]{GLYPH_CHECK} Installed[/green]",
                f"[green]{ver_text}[/green]",
                status.path or "",
            )
        else:
            missing_tools.append(name)
            tool_table.add_row(
                f"[bold]{name}[/bold]",
                f"[red]{GLYPH_CROSS} Missing[/red]",
                "[dim]--[/dim]",
                "[dim]Not found in PATH[/dim]",
            )

    console.print(tool_table)
    console.print()

    if install_missing:
        if missing_tools:
            console.print(f"[bold yellow]Installing {len(missing_tools)} missing tools into ~/.astrarecon/bin...[/bold yellow]\n")
            ToolInstaller.install_all_missing(missing_tools, console)
            console.print("\n[bold cyan]Re-evaluating environment diagnostics...[/bold cyan]\n")
            # Refresh and display updated tool status
            env = EnvironmentInspector.inspect()
            new_missing = [n for n, s in env.tools.items() if not s.installed]
            if not new_missing:
                console.print(f"[bold green]{GLYPH_CHECK} All missing tools successfully installed![/bold green]\n")
            else:
                console.print(f"[yellow]{len(new_missing)} tool(s) still missing: {', '.join(new_missing)}[/yellow]\n")
        else:
            console.print(f"[bold green]{GLYPH_CHECK} All core tools are already installed. No action needed.[/bold green]\n")
    elif missing_tools:
        console.print(
            Panel(
                f"[bold yellow]Missing Tools Detected ({len(missing_tools)}):[/bold yellow] {', '.join(missing_tools)}\n\n"
                f"[dim]Tip:[/dim] Run [bold green]astrarecon doctor --install-missing[/bold green] "
                f"to automatically fetch official binaries into ~/.astrarecon/bin/.",
                title="Actionable Remediation",
                border_style="yellow",
            )
        )
    else:
        console.print(f"[bold green]{GLYPH_CHECK} All core reconnaissance tools are installed and ready to execute![/bold green]\n")
