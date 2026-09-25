"""Unit tests for AstraRecon Rich CLI UX Components."""

import pytest
from rich.panel import Panel
from rich.text import Text

from astrarecon.cli.ui.components import (
    CompletionSummaryView,
    PluginListComponent,
    QuickCommandsComponent,
    StartupScreen,
    StatusPanel,
    SystemInfoComponent,
    TelemetryCollector,
)
from astrarecon.cli.ui.theme import (
    COLOR_ACCENT,
    COLOR_PRIMARY,
    COLOR_SUCCESS,
    STATUS_ICONS,
)
from astrarecon.core.models.session import NodeExecutionStatus


def test_telemetry_collector():
    """Verify telemetry collection returns all required dynamic fields."""
    metrics = TelemetryCollector.collect()

    assert "version" in metrics
    assert "platform" in metrics
    assert "workflow_mode" in metrics
    assert "installed_plugins" in metrics
    assert "missing_plugins" in metrics
    assert "installed_count" in metrics
    assert "missing_count" in metrics
    assert "session_count" in metrics
    assert "last_scan" in metrics
    assert "cache_size" in metrics


def test_system_info_component():
    """Verify system information component renders required metrics."""
    metrics = {
        "version": "v1.0.0-dev",
        "platform": "Linux • WSL",
        "workflow_mode": "DAG • Persistent Sessions",
        "installed_count": 6,
        "missing_count": 2,
        "session_count": 3,
        "last_scan": "example.com",
        "cache_size": "12.4 MB",
    }
    table = SystemInfoComponent.render(metrics)
    assert table is not None


def test_startup_screen_render():
    """Verify startup screen renders as a rounded Panel with proper branding."""
    panel = StartupScreen.render()
    assert isinstance(panel, Panel)
    assert panel.border_style is not None


def test_status_panel_lifecycle():
    """Verify live status panel updates nodes through various states."""
    nodes = ["subfinder", "dnsx", "httpx"]
    panel = StatusPanel(target="example.com", node_ids=nodes)

    # Initially waiting
    for nid in nodes:
        assert panel.node_statuses[nid] == "WAITING"

    # Running
    panel.update_status("subfinder", NodeExecutionStatus.RUNNING)
    assert panel.node_statuses["subfinder"] == "RUNNING"

    # Completed with items
    panel.update_status("subfinder", NodeExecutionStatus.COMPLETED, item_count=42)
    assert panel.node_statuses["subfinder"] == "SUCCESS"
    assert panel.node_items["subfinder"] == 42

    # Cached
    panel.update_status("dnsx", "CACHED")
    assert panel.node_statuses["dnsx"] == "CACHED"

    # Failed with message
    panel.update_status("httpx", "FAILED", message="Binary missing from PATH")
    assert panel.node_statuses["httpx"] == "FAILED"
    assert len(panel.notices) == 1
    assert "Binary missing from PATH" in panel.notices[0]

    # Render check
    rendered = panel.render()
    assert isinstance(rendered, Panel)


def test_status_icons_mapping():
    """Verify all 7 required status states have corresponding icons and colors."""
    required_states = ["RUNNING", "WAITING", "SUCCESS", "RETRY", "FAILED", "CACHED", "SKIPPED"]
    for state in required_states:
        assert state in STATUS_ICONS
        icon, color = STATUS_ICONS[state]
        assert len(icon) > 0
        assert color.startswith("#")


def test_completion_summary_view():
    """Verify post-scan completion summary card renders properly."""
    card = CompletionSummaryView.render(
        target="example.com",
        duration_seconds=12.4,
        session_id="2026-09-26-001-example-com",
        total_subdomains=42,
        live_hosts=18,
        ai_bundle_path="C:/path/to/exports",
    )
    assert isinstance(card, Panel)


def test_help_menu_view():
    """Verify enhanced help menu renders as a complete Panel."""
    from astrarecon.cli.ui.help import HelpMenuView

    help_panel = HelpMenuView.render()
    assert isinstance(help_panel, Panel)
    assert help_panel.title is not None
