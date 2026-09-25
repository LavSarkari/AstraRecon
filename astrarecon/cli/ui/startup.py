"""Startup Interface Component for AstraRecon."""

from rich.panel import Panel

from astrarecon.cli.ui.components import (
    PluginListComponent,
    QuickCommandsComponent,
    StartupScreen,
    SystemInfoComponent,
    TelemetryCollector,
)


class StartupView(StartupScreen):
    """Backwards-compatible wrapper around StartupScreen."""

    @classmethod
    def get_runtime_metrics(cls) -> dict:
        return TelemetryCollector.collect()

    @classmethod
    def render(cls) -> Panel:
        return StartupScreen.render()
