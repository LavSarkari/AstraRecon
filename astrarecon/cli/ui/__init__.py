"""UI components package for AstraRecon."""

from astrarecon.cli.ui.components import (
    CompletionSummaryView,
    PluginListComponent,
    QuickCommandsComponent,
    StartupScreen,
    StatusPanel,
    SystemInfoComponent,
    TelemetryCollector,
)
from astrarecon.cli.ui.live_panel import LiveScanView
from astrarecon.cli.ui.startup import StartupView
from astrarecon.cli.ui.theme import (
    COLOR_ACCENT,
    COLOR_BG,
    COLOR_DIVIDER,
    COLOR_ERROR,
    COLOR_PRIMARY,
    COLOR_SECONDARY,
    COLOR_SUCCESS,
    COLOR_WARNING,
    PANEL_BOX,
    STATUS_ICONS,
)

__all__ = [
    "COLOR_BG",
    "COLOR_PRIMARY",
    "COLOR_SECONDARY",
    "COLOR_ACCENT",
    "COLOR_DIVIDER",
    "COLOR_SUCCESS",
    "COLOR_WARNING",
    "COLOR_ERROR",
    "STATUS_ICONS",
    "PANEL_BOX",
    "StartupScreen",
    "StartupView",
    "StatusPanel",
    "LiveScanView",
    "SystemInfoComponent",
    "PluginListComponent",
    "QuickCommandsComponent",
    "CompletionSummaryView",
    "TelemetryCollector",
]
