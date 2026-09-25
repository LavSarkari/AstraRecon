"""Reusable Rich UI Components for AstraRecon.

Components:
- SystemInfoComponent: Engine, platform, workflow mode, sessions, cache, plugin counts.
- PluginListComponent: Installed and available reconnaissance plugin list.
- QuickCommandsComponent: Common developer CLI invocations and hints.
- StartupScreen: Polished, rounded, persistent startup panel.
- StatusPanel: In-place live scan execution panel.
- CompletionSummaryView: Post-scan completion metrics card.
"""

import json
import os
import platform
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
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
    SPINNER_FRAMES,
    STATUS_ICONS,
    USE_UNICODE,
)
from astrarecon.core.doctor.inspector import EnvironmentInspector
from astrarecon.core.models.session import NodeExecutionStatus
from astrarecon.core.plugins.loader import PluginLoader


# =============================================================================
# Telemetry Collector
# =============================================================================

class TelemetryCollector:
    """Collects real-time engine, system, plugin, session, and CAS metrics."""

    @classmethod
    def collect(cls) -> dict:
        env = EnvironmentInspector.inspect()

        # Accurate Host Platform Detection
        machine = platform.machine() or env.arch
        is_wsl = "microsoft" in platform.uname().release.lower()
        if is_wsl:
            distro_name = env.os_name if env.os_name != "Linux" else "Linux"
            plat_str = f"{distro_name} {BULLET_ICON} WSL ({machine})"
        elif platform.system() == "Linux":
            plat_str = f"{env.os_name} ({machine})"
        elif platform.system() == "Windows":
            win_ver = platform.release()
            try:
                build = int(platform.version().split(".")[2])
                if build >= 22000:
                    win_ver = "11"
            except Exception:
                pass
            plat_str = f"Windows {win_ver} ({machine})"
        elif platform.system() == "Darwin":
            plat_str = f"macOS {platform.mac_ver()[0]} ({machine})"
        else:
            plat_str = f"{platform.system()} {platform.release()} ({machine})"

        # Dynamic Plugin Discovery from PluginRegistry
        plugin_registry = PluginLoader.load_all_plugins()
        all_manifests = plugin_registry.list_all()

        installed_plugins = []
        missing_plugins = []

        managed_bin = EnvironmentInspector.get_managed_bin_dir()

        for manifest in all_manifests:
            bin_name = manifest.binary.name
            tool_status = env.tools.get(bin_name)
            is_installed = False

            if tool_status and tool_status.installed:
                is_installed = True
            elif shutil.which(bin_name):
                is_installed = True
            elif (managed_bin / bin_name).is_file() or (managed_bin / f"{bin_name}.exe").is_file():
                is_installed = True

            if is_installed:
                installed_plugins.append(manifest.id)
            else:
                missing_plugins.append(manifest.id)

        # Dynamic Cached Sessions count & Last Scan telemetry
        sessions_dir = Path.home() / ".astrarecon" / "sessions"
        session_count = 0
        last_scan_display = "None"
        last_target = "example.com"

        if sessions_dir.exists():
            sessions = sorted(
                [d for d in sessions_dir.iterdir() if d.is_dir() and (d / "session.json").exists()],
                key=lambda x: x.stat().st_mtime,
                reverse=True,
            )
            session_count = len(sessions)
            if sessions:
                try:
                    with open(sessions[0] / "session.json", "r", encoding="utf-8") as f:
                        data = json.load(f)
                    target = data.get("target", "unknown")
                    last_target = target

                    # Compute dynamic relative time
                    delta_sec = time.time() - sessions[0].stat().st_mtime
                    if delta_sec < 60:
                        rel_time = "just now"
                    elif delta_sec < 3600:
                        rel_time = f"{int(delta_sec // 60)}m ago"
                    elif delta_sec < 86400:
                        rel_time = f"{int(delta_sec // 3600)}h ago"
                    else:
                        rel_time = f"{int(delta_sec // 86400)}d ago"

                    last_scan_display = f"{target} ({rel_time})"
                except Exception:
                    last_scan_display = sessions[0].name.split("-")[0]

        # Dynamic CAS Cache size & Blobs
        cache_dir = Path.home() / ".astrarecon" / "cache" / "blobs"
        cache_size_str = "0 MB"
        blob_count = 0
        if cache_dir.exists():
            blobs = [f for f in cache_dir.rglob("*") if f.is_file()]
            blob_count = len(blobs)
            total_bytes = sum(f.stat().st_size for f in blobs)
            if total_bytes > (1024 * 1024):
                cache_size_str = f"{total_bytes / (1024 * 1024):.1f} MB"
            elif total_bytes > 0:
                cache_size_str = f"{total_bytes / 1024:.1f} KB"
            else:
                cache_size_str = "0 MB"

        return {
            "version": f"v{__version__}",
            "platform": plat_str,
            "workflow_mode": f"DAG {BULLET_ICON} Persistent Sessions",
            "installed_plugins": installed_plugins,
            "missing_plugins": missing_plugins,
            "installed_count": len(installed_plugins),
            "missing_count": len(missing_plugins),
            "session_count": session_count,
            "last_scan": last_scan_display,
            "last_target": last_target,
            "cache_size": cache_size_str,
            "blob_count": blob_count,
        }


# =============================================================================
# Component 1: System Information
# =============================================================================

class SystemInfoComponent:
    """Renders the engine specs, host environment, workflow mode, and cache telemetry."""

    @staticmethod
    def render(metrics: dict) -> Table:
        table = Table.grid(padding=(0, 2))
        table.add_column(style=f"{COLOR_SECONDARY}", width=14)
        table.add_column(style=f"bold {COLOR_PRIMARY}")

        table.add_row("Engine", metrics["version"])
        table.add_row("Platform", metrics["platform"])

        # Dynamic session & cache stats
        if metrics.get("session_count", 0) > 0:
            sess_str = f"{metrics['session_count']} recorded ({BULLET_ICON} Last: {metrics['last_scan']})"
        else:
            sess_str = "0 recorded"
        table.add_row("Sessions", sess_str)
        table.add_row("Cache", metrics["cache_size"])

        # Plugin counts
        plug_str = f"{metrics['installed_count']} ready {BULLET_ICON} {metrics['missing_count']} missing"
        table.add_row("Plugins", plug_str)

        return table


# =============================================================================
# Component 2: Plugin List
# =============================================================================

class PluginListComponent:
    """Renders the dynamically discovered plugins with real-time availability."""

    @staticmethod
    def render(metrics: dict) -> RenderableType:
        title = Text("Installed Plugins", style=f"bold {COLOR_PRIMARY}")

        installed = sorted(metrics.get("installed_plugins", []))
        missing = sorted(metrics.get("missing_plugins", []))

        # Combine all dynamically discovered plugins
        all_items = [(p, True) for p in installed] + [(p, False) for p in missing]

        if not all_items:
            hint = Text("No plugins discovered. Check ~/.astrarecon/plugins", style=f"dim {COLOR_SECONDARY}")
            return Group(title, Text(""), hint)

        # Render in 2 balanced columns
        grid = Table.grid(padding=(0, 4))
        grid.add_column(width=22)
        grid.add_column(width=22)

        for i in range(0, len(all_items), 2):
            col1 = all_items[i]
            col2 = all_items[i + 1] if i + 1 < len(all_items) else None

            def format_item(item: Optional[tuple[str, bool]]) -> Text:
                if not item:
                    return Text("")
                name, is_inst = item
                t = Text()
                if is_inst:
                    t.append(f"{CHECK_ICON} ", style=f"bold {COLOR_SUCCESS}")
                    t.append(name, style=COLOR_PRIMARY)
                else:
                    empty_glyph = "○ " if USE_UNICODE else "- "
                    t.append(empty_glyph, style=f"dim {COLOR_SECONDARY}")
                    t.append(name, style=f"dim {COLOR_SECONDARY}")
                return t

            grid.add_row(format_item(col1), format_item(col2))

        return Group(title, Text(""), grid)


# =============================================================================
# Component 3: Quick Commands
# =============================================================================

class QuickCommandsComponent:
    """Renders the quick command reference dynamically grounded in recent target."""

    @staticmethod
    def render(last_target: Optional[str] = None) -> RenderableType:
        title = Text("Quick Commands & Cheat Sheet", style=f"bold {COLOR_PRIMARY}")

        target_hint = last_target or "example.com"
        table = Table.grid(padding=(0, 2))
        table.add_column(width=36)
        table.add_column(style=f"{COLOR_SECONDARY}")

        items = [
            (f"astrarecon scan {target_hint}", "Launch full-spectrum DAG recon scan"),
            (f"astrarecon scan {target_hint} --fresh", "Start new session (skip resume prompt)"),
            ("astrarecon doctor --install-missing", "Auto-fetch & compile missing security tools"),
            ("astrarecon sessions list", "View all scan sessions & completion stats"),
            ("astrarecon sessions inspect <id>", "Deep inspect checkpoints, timing & logs"),
            ("astrarecon plugins list", "List 13 security tool binaries & versions"),
            ("astrarecon --help", "Open comprehensive interactive manual"),
        ]

        for cmd, desc in items:
            parts = cmd.split(" ", 2)
            cmd_text = Text()
            cmd_text.append(parts[0], style=f"{COLOR_ACCENT}")
            if len(parts) > 1:
                cmd_text.append(f" {parts[1]}", style=f"bold {COLOR_PRIMARY}")
            if len(parts) > 2:
                cmd_text.append(f" {parts[2]}", style=f"{COLOR_SECONDARY}")
            table.add_row(cmd_text, Text(f"─ {desc}", style=f"dim {COLOR_SECONDARY}"))

        hint = Text(f"\nType 'astrarecon scan {target_hint}' to launch, or 'astrarecon --help' for options.", style=f"dim {COLOR_SECONDARY}")

        return Group(title, Text(""), table, hint)


# =============================================================================
# Component 4: Startup Screen
# =============================================================================

class StartupScreen:
    """Combines branding, telemetry, plugins, and commands inside a single persistent panel."""

    @classmethod
    def render(cls) -> Panel:
        metrics = TelemetryCollector.collect()

        # Branding Header: ASTRA (white) RECON (blue)
        title = Text()
        title.append("ASTRA", style=f"bold {COLOR_PRIMARY}")
        title.append("RECON", style=f"bold {COLOR_ACCENT}")

        # Tagline: Visual Recon Workflow Engine
        tagline = Text("Visual Recon Workflow Engine", style=f"{COLOR_SECONDARY}")
        header_group = Group(title, tagline)

        # Subtle divider lines (#1E293B)
        divider = Text(DIVIDER_CHAR * 56, style=f"{COLOR_DIVIDER}")

        # Dynamic Subcomponents
        sys_info = SystemInfoComponent.render(metrics)
        plugin_list = PluginListComponent.render(metrics)
        quick_cmds = QuickCommandsComponent.render(metrics.get("last_target"))

        content = Group(
            header_group,
            divider,
            sys_info,
            divider,
            plugin_list,
            divider,
            quick_cmds,
        )

        return Panel(
            content,
            box=PANEL_BOX,
            border_style=COLOR_DIVIDER,
            padding=(1, 3),
            expand=False,
        )


# =============================================================================
# Component 5: Status Panel (Live Scan Panel)
# =============================================================================

class StatusPanel:
    """Compact live-updating status panel replacing the startup screen during active runs.
    
    Provides live timer, active node elapsed progression, animated spinner, and
    transparent feedback on tool operations, warnings, and missing dependencies.
    """

    def __init__(
        self,
        target: str,
        node_ids: list[str],
        workflow_id: Optional[str] = None,
        node_labels: Optional[dict[str, str]] = None,
    ):
        self.target = target
        self.workflow_id = workflow_id or "default"
        self.node_ids = node_ids
        self.node_labels = node_labels or {}
        self.node_statuses: dict[str, str] = {nid: "WAITING" for nid in node_ids}
        self.node_durations: dict[str, float] = {nid: 0.0 for nid in node_ids}
        self.node_items: dict[str, int] = {nid: 0 for nid in node_ids}
        self.node_messages: dict[str, str] = {}
        self.notices: list[str] = []
        self.current_activity: Optional[str] = None
        self.start_times: dict[str, float] = {}
        self.scan_start_time = time.time()

    def add_notice(self, notice: str) -> None:
        """Appends a clear status notice or warning if not already recorded."""
        if notice and notice not in self.notices:
            self.notices.append(notice)

    def set_activity(self, activity: Optional[str]) -> None:
        """Sets an explicit high-level activity description."""
        self.current_activity = activity

    def update_status(
        self,
        node_id: str,
        status: NodeExecutionStatus | str,
        item_count: Optional[int] = None,
        message: Optional[str] = None,
    ):
        """Updates internal status, timestamps, item yields, and notices for a given node."""
        status_key = status.value if hasattr(status, "value") else str(status).upper()

        if status_key == "RUNNING":
            self.node_statuses[node_id] = "RUNNING"
            self.start_times[node_id] = time.time()
        elif status_key in ("COMPLETED", "SUCCESS"):
            self.node_statuses[node_id] = "SUCCESS"
            if node_id in self.start_times:
                self.node_durations[node_id] = time.time() - self.start_times[node_id]
        elif status_key == "FAILED":
            self.node_statuses[node_id] = "FAILED"
            if node_id in self.start_times:
                self.node_durations[node_id] = time.time() - self.start_times[node_id]
        elif status_key == "CACHED":
            self.node_statuses[node_id] = "CACHED"
        elif status_key == "SKIPPED":
            self.node_statuses[node_id] = "SKIPPED"
        elif status_key == "RETRY":
            self.node_statuses[node_id] = "RETRY"

        if item_count is not None:
            self.node_items[node_id] = item_count

        if message:
            self.node_messages[node_id] = message
            display_name = self.node_labels.get(node_id, node_id.replace("_", " ").title())
            if status_key == "FAILED":
                self.add_notice(f"{display_name}: {message}")

    def render(self) -> Panel:
        """Constructs the persistent live panel renderable with dynamic timer and feedback."""
        elapsed = time.time() - self.scan_start_time
        mins, secs = divmod(int(elapsed), 60)
        time_str = f"{mins:02d}:{secs:02d}"

        # Title: ASTRA (white) RECON (blue)
        title_text = Text()
        title_text.append(" ASTRA", style=f"bold {COLOR_PRIMARY}")
        title_text.append("RECON ", style=f"bold {COLOR_ACCENT}")
        if self.target:
            title_text.append(f" {DIVIDER_CHAR} {self.target} ", style=f"{COLOR_SECONDARY}")
        title_text.append(f"[{time_str}] ", style=f"bold {COLOR_ACCENT}")

        # Table rows for each node
        table = Table.grid(padding=(0, 2))
        table.add_column(width=4)   # Status Icon / Spinner
        table.add_column(width=22)  # Node / Tool Name
        table.add_column(width=14)  # State Label
        table.add_column(width=10)  # Elapsed Duration (live ticking)
        table.add_column(width=16)  # Item Count or Error Reason

        # Animated spinner frame for running nodes
        spin_idx = int(time.time() * 8) % len(SPINNER_FRAMES)
        live_spinner = SPINNER_FRAMES[spin_idx]

        active_running_nodes = []

        for nid in self.node_ids:
            state = self.node_statuses.get(nid, "WAITING")

            # Display friendly node name
            if nid in self.node_labels:
                display_name = self.node_labels[nid]
            else:
                clean_name = nid.replace("plugin.", "").replace("builtin.", "").replace("_", " ").strip()
                display_name = clean_name.title()

            # Dynamic icon and duration computation
            if state == "RUNNING":
                active_running_nodes.append((display_name, nid))
                icon = live_spinner
                color = COLOR_ACCENT
                cur_dur = time.time() - self.start_times.get(nid, time.time())
                dur_str = f"{cur_dur:.1f}s"
                status_label = "Running"
                items_str = "in progress"
                items_style = f"dim {COLOR_SECONDARY}"
                name_style = f"bold {COLOR_PRIMARY}"
            elif state in ("SUCCESS", "COMPLETED"):
                icon, color = STATUS_ICONS.get("SUCCESS", ("✔", COLOR_SUCCESS))
                status_label = "Success"
                dur_val = self.node_durations.get(nid, 0.0)
                dur_str = f"{dur_val:.1f}s"
                count = self.node_items.get(nid, 0)
                items_str = f"{count} items" if count > 0 else "--"
                items_style = f"{COLOR_ACCENT}" if count > 0 else f"dim {COLOR_SECONDARY}"
                name_style = COLOR_PRIMARY
            elif state == "FAILED":
                icon, color = STATUS_ICONS.get("FAILED", ("✖", COLOR_ERROR))
                status_label = "Failed"
                dur_val = self.node_durations.get(nid, 0.0)
                dur_str = f"{dur_val:.1f}s"
                msg = self.node_messages.get(nid, "")
                if "missing" in msg.lower() or "not found" in msg.lower():
                    items_str = "missing bin"
                else:
                    items_str = "failed"
                items_style = f"{COLOR_ERROR}"
                name_style = COLOR_PRIMARY
            elif state == "CACHED":
                icon, color = STATUS_ICONS.get("CACHED", ("◈", COLOR_ACCENT))
                status_label = "Cached"
                dur_str = "cached"
                count = self.node_items.get(nid, 0)
                items_str = f"{count} items" if count > 0 else "--"
                items_style = f"{COLOR_ACCENT}" if count > 0 else f"dim {COLOR_SECONDARY}"
                name_style = COLOR_PRIMARY
            elif state == "SKIPPED":
                icon, color = STATUS_ICONS.get("SKIPPED", ("○", COLOR_SECONDARY))
                status_label = "Skipped"
                dur_str = "--"
                items_str = "--"
                items_style = f"dim {COLOR_SECONDARY}"
                name_style = f"dim {COLOR_SECONDARY}"
            else:  # WAITING
                icon, color = STATUS_ICONS.get("WAITING", ("●", COLOR_SECONDARY))
                status_label = "Waiting"
                dur_str = "--"
                items_str = ""
                items_style = f"dim {COLOR_SECONDARY}"
                name_style = COLOR_SECONDARY

            table.add_row(
                Text(icon, style=f"bold {color}"),
                Text(display_name, style=name_style),
                Text(status_label, style=f"{color}"),
                Text(dur_str, style=f"{color}" if state == "RUNNING" else f"dim {COLOR_SECONDARY}"),
                Text(items_str, style=items_style),
            )

        # Dynamic Feedback & Activity Section
        feedback_lines = []

        if active_running_nodes:
            active_names = []
            for name, nid in active_running_nodes:
                c_dur = time.time() - self.start_times.get(nid, time.time())
                active_names.append(f"{name} ({c_dur:.1f}s)")
            feedback_lines.append(
                Text(f" {live_spinner} Active: {', '.join(active_names)}", style=f"bold {COLOR_ACCENT}")
            )
        elif all(self.node_statuses.get(nid) in ("SUCCESS", "FAILED", "CACHED", "SKIPPED") for nid in self.node_ids):
            completed_count = sum(1 for nid in self.node_ids if self.node_statuses.get(nid) in ("SUCCESS", "CACHED"))
            feedback_lines.append(
                Text(f" {CHECK_ICON} Pipeline execution finished ({completed_count}/{len(self.node_ids)} stages succeeded)", style=f"bold {COLOR_SUCCESS}")
            )

        # Render recent warnings or error notices
        for notice in self.notices[-2:]:
            feedback_lines.append(
                Text(f" ! Notice: {notice}", style=f"{COLOR_WARNING}")
            )

        if feedback_lines:
            panel_divider = Text(" " + DIVIDER_CHAR * 56, style=COLOR_DIVIDER)
            panel_content = Group(
                table,
                panel_divider,
                *feedback_lines,
            )
        else:
            panel_content = table

        return Panel(
            panel_content,
            title=title_text,
            title_align="left",
            box=PANEL_BOX,
            border_style=COLOR_DIVIDER,
            padding=(1, 2),
            expand=False,
        )


# =============================================================================
# Component 6: Completion Summary
# =============================================================================

class CompletionSummaryView:
    """Renders a post-scan summary card upon workflow completion."""

    @staticmethod
    def render(
        target: str,
        duration_seconds: float,
        session_id: str,
        total_subdomains: int = 0,
        live_hosts: int = 0,
        vulnerabilities: int = 0,
        ai_bundle_path: Optional[str] = None,
    ) -> Panel:
        mins, secs = divmod(int(duration_seconds), 60)

        header = Text()
        check = "✔ " if USE_UNICODE else "[OK] "
        header.append(check, style=f"bold {COLOR_SUCCESS}")
        header.append("Scan Completed", style=f"bold {COLOR_PRIMARY}")
        header.append(f" for {target}", style=f"bold {COLOR_ACCENT}")
        header.append(f" in {mins:02d}m {secs:02d}s", style=f"dim {COLOR_SECONDARY}")

        details_table = Table.grid(padding=(0, 2))
        details_table.add_column(style=f"{COLOR_SECONDARY}", width=18)
        details_table.add_column(style=f"bold {COLOR_PRIMARY}")

        details_table.add_row("Session ID", session_id)
        if total_subdomains > 0:
            details_table.add_row("Subdomains", str(total_subdomains))
        if live_hosts > 0:
            details_table.add_row("Live HTTP Hosts", str(live_hosts))
        if vulnerabilities > 0:
            details_table.add_row("Vulnerabilities", str(vulnerabilities))
        if ai_bundle_path:
            details_table.add_row("AI Export Bundle", str(ai_bundle_path))

        divider = Text(DIVIDER_CHAR * 50, style=COLOR_DIVIDER)
        footer = Text(f"\nRun 'astrarecon export ai {session_id}' to inspect prompt bundle.", style=f"dim {COLOR_SECONDARY}")

        content = Group(
            header,
            divider,
            details_table,
            footer,
        )

        return Panel(
            content,
            box=PANEL_BOX,
            border_style=COLOR_SUCCESS,
            padding=(1, 3),
            expand=False,
        )
