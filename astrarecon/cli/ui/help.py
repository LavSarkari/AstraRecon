"""Enhanced Rich Help Menu and Command Manual for AstraRecon."""

from typing import Optional
from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from astrarecon import __version__
from astrarecon.cli.ui.theme import (
    BULLET_ICON,
    CHECK_ICON,
    COLOR_ACCENT,
    COLOR_DIVIDER,
    COLOR_ERROR,
    COLOR_PRIMARY,
    COLOR_SECONDARY,
    COLOR_SUCCESS,
    COLOR_WARNING,
    DIVIDER_CHAR,
    PANEL_BOX,
)


class HelpMenuView:
    """Renders a comprehensive, visually stunning AstraRecon CLI Manual."""

    @classmethod
    def render(cls) -> Panel:
        divider = Text(DIVIDER_CHAR * 72, style=COLOR_DIVIDER)

        # 1. Branding Header
        header = Text()
        header.append(" ASTRA", style=f"bold {COLOR_PRIMARY}")
        header.append("RECON", style=f"bold {COLOR_ACCENT}")
        header.append(f"  v{__version__}", style=f"bold {COLOR_SUCCESS}")
        header.append("  ─  Visual Reconnaissance & DAG Workflow Engine\n", style=f"dim {COLOR_SECONDARY}")
        header.append("  Author: ", style=f"dim {COLOR_SECONDARY}")
        header.append("LavSarkari", style=f"bold {COLOR_PRIMARY}")
        header.append(f" {BULLET_ICON} Architecture: ", style=f"dim {COLOR_SECONDARY}")
        header.append("Linux-First DAG • Process-Isolated Workers • CAS Cache", style=f"{COLOR_ACCENT}")

        # 2. Syntax & General Usage
        usage_table = Table.grid(padding=(0, 2))
        usage_table.add_column(style=f"bold {COLOR_PRIMARY}", width=12)
        usage_table.add_column(style=f"{COLOR_SECONDARY}")

        usage_table.add_row(
            Text("Usage:", style=f"bold {COLOR_ACCENT}"),
            Text("astrarecon [COMMAND] [OPTIONS] [ARGUMENTS]", style=f"bold {COLOR_PRIMARY}"),
        )
        usage_table.add_row(
            Text("Quick Start:", style=f"bold {COLOR_ACCENT}"),
            Text("astrarecon scan example.com", style=f"bold {COLOR_SUCCESS}"),
        )

        # 3. Core Commands Section
        cmds_title = Text("CORE COMMANDS", style=f"bold {COLOR_PRIMARY}")

        cmd_table = Table(
            show_header=True,
            header_style=f"bold {COLOR_ACCENT}",
            box=box.SIMPLE_HEAD,
            padding=(0, 2),
            expand=True,
        )
        cmd_table.add_column("Command", style=f"bold {COLOR_PRIMARY}", width=18)
        cmd_table.add_column("Usage / Target", style=f"{COLOR_ACCENT}", width=26)
        cmd_table.add_column("Description", style=f"{COLOR_SECONDARY}")

        cmd_table.add_row(
            "scan",
            "<target> [flags]",
            "Execute automated multi-tool DAG reconnaissance scan",
        )
        cmd_table.add_row(
            "doctor",
            "[--install-missing]",
            "Audit runtime environment, Go compiler, and 13 tool binaries",
        )
        cmd_table.add_row(
            "sessions list",
            "",
            "List all recorded scan sessions, age, status, and completion %",
        )
        cmd_table.add_row(
            "sessions inspect",
            "<session_id>",
            "Deep diagnostic: examine checkpoint outputs, timing & error logs",
        )
        cmd_table.add_row(
            "sessions prune",
            "[--days N] [--force]",
            "Clean up old/failed scan sessions and reclaim filesystem disk space",
        )
        cmd_table.add_row(
            "sessions delete",
            "<session_id> [--force]",
            "Permanently delete a specific session directory and its artifacts",
        )
        cmd_table.add_row(
            "plugins list",
            "",
            "Display all 13 integrated tools, binary paths, and versions",
        )
        cmd_table.add_row(
            "plugins info",
            "<plugin_id>",
            "Inspect input/output types, CLI arguments vector, and cache policy",
        )
        cmd_table.add_row(
            "cache stats",
            "",
            "View Content-Addressed Store (CAS) disk usage and blob metrics",
        )
        cmd_table.add_row(
            "cache prune",
            "[--older-than N]",
            "Evict expired CAS artifact blobs to free disk storage",
        )

        # 4. Scan Flags & Options
        scan_title = Text("SCAN COMMAND OPTIONS  ('astrarecon scan <target>')", style=f"bold {COLOR_PRIMARY}")

        flags_table = Table(
            show_header=True,
            header_style=f"bold {COLOR_ACCENT}",
            box=box.SIMPLE_HEAD,
            padding=(0, 2),
            expand=True,
        )
        flags_table.add_column("Option / Flag", style=f"bold {COLOR_PRIMARY}", width=26)
        flags_table.add_column("Type / Choices", style=f"{COLOR_ACCENT}", width=18)
        flags_table.add_column("Description", style=f"{COLOR_SECONDARY}")

        flags_table.add_row(
            "--workflow, -w",
            "default",
            "Workflow definition to execute (default: 7-stage DAG pipeline)",
        )
        flags_table.add_row(
            "--profile, -p",
            "auto | safe | beast",
            "Concurrency and execution throttle profile",
        )
        flags_table.add_row(
            "--resume, -r",
            "<session_id>",
            "Resume a previously paused, interrupted, or failed session",
        )
        flags_table.add_row(
            "--fresh, -f",
            "flag",
            "Bypass existing session prompt and force start a fresh scan",
        )
        flags_table.add_row(
            "--diff-only",
            "flag",
            "Continuous recon: scan only newly discovered attack surfaces",
        )
        flags_table.add_row(
            "--proxy",
            "http(s):// / socks5://",
            "Route scanner network traffic through upstream HTTP/SOCKS5 proxy",
        )
        flags_table.add_row(
            "--header, -H",
            "Header: Value",
            "Inject custom HTTP header into network scanners (repeatable)",
        )
        flags_table.add_row(
            "--scope-include",
            "regex",
            "Regex pattern matching strictly authorized in-scope targets",
        )
        flags_table.add_row(
            "--scope-exclude",
            "regex",
            "Regex pattern of targets to quarantine away from scans",
        )

        # 5. Supported Target Formats
        targets_title = Text("SUPPORTED TARGET FORMATS", style=f"bold {COLOR_PRIMARY}")

        targets_table = Table.grid(padding=(0, 2))
        targets_table.add_column(style=f"bold {COLOR_ACCENT}", width=20)
        targets_table.add_column(style=f"bold {COLOR_PRIMARY}", width=32)
        targets_table.add_column(style=f"{COLOR_SECONDARY}")

        targets_table.add_row("FQDN / Domain", "astrarecon scan example.com", "Standard apex domain discovery")
        targets_table.add_row("Wildcard Domain", "astrarecon scan *.example.com", "Auto-normalizes wildcard target for scanners")
        targets_table.add_row("Web Application", "astrarecon scan https://target.io", "Extracts hostname and protocol context")
        targets_table.add_row("IPv4 Address", "astrarecon scan 192.168.1.1", "Single host recon and port probing")
        targets_table.add_row("Network CIDR", "astrarecon scan 10.0.0.0/24", "Subnet scanning & attack surface mapping")

        # 6. Integrated Tool Pipeline
        tools_title = Text("INTEGRATED SECURITY ARSENAL (13 TOOLS)", style=f"bold {COLOR_PRIMARY}")

        tools_grid = Table.grid(padding=(0, 2))
        tools_grid.add_column(style=f"bold {COLOR_ACCENT}", width=24)
        tools_grid.add_column(style=f"{COLOR_PRIMARY}")

        tools_grid.add_row("Subdomain Discovery:", "subfinder, assetfinder, amass, subenum")
        tools_grid.add_row("DNS & Active Probing:", "dnsx, httpx, naabu")
        tools_grid.add_row("Web Crawl & JS Analysis:", "katana, gau, waybackurls, linkfinder")
        tools_grid.add_row("Vulnerability Scanning:", "nuclei, dalfox")

        # 7. Actionable Tips Footer
        footer = Text()
        footer.append(" Tips & Help:\n", style=f"bold {COLOR_PRIMARY}")
        footer.append(f"  {BULLET_ICON} Run ", style=f"dim {COLOR_SECONDARY}")
        footer.append("astrarecon doctor --install-missing", style=f"bold {COLOR_ACCENT}")
        footer.append(" to automatically install and verify all 13 tools.\n", style=f"dim {COLOR_SECONDARY}")
        footer.append(f"  {BULLET_ICON} Run ", style=f"dim {COLOR_SECONDARY}")
        footer.append("astrarecon [command] --help", style=f"bold {COLOR_ACCENT}")
        footer.append(" for specific flags, arguments, and advanced options.\n", style=f"dim {COLOR_SECONDARY}")
        footer.append(f"  {BULLET_ICON} Scan sessions are fully resumable with zero duplicate API/tool work.", style=f"dim {COLOR_SECONDARY}")

        content = Group(
            header,
            divider,
            usage_table,
            divider,
            cmds_title,
            cmd_table,
            divider,
            scan_title,
            flags_table,
            divider,
            targets_title,
            targets_table,
            divider,
            tools_title,
            tools_grid,
            divider,
            footer,
        )

        return Panel(
            content,
            title="[bold white]ASTRA[/bold white][bold #1DA1FF]RECON[/bold #1DA1FF] [dim]─ Comprehensive Command Manual[/dim]",
            title_align="left",
            box=PANEL_BOX,
            border_style=COLOR_DIVIDER,
            padding=(1, 3),
            expand=False,
        )
