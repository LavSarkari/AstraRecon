"""AstraRecon Cosmic UI Loader.

Provides rich celestial-themed animated spinners and transient telemetry indicators
for startup calibration, plugin scanning, update checks, and engine staging.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

from rich._spinners import SPINNERS
from rich.console import Console

from astrarecon.cli.ui.theme import COLOR_ACCENT, COLOR_PRIMARY, USE_UNICODE

# Register celestial Astra constellation spinners into Rich's spinner registry
ASTRA_SPINNER_FRAMES = [
    "✦ ⠋ ⋆",
    "✧ ⠙ ✦",
    "⋆ ⠹ ✧",
    "✵ ⠸ ⋆",
    "✹ ⠼ ✵",
    "✺ ⠴ ✹",
    "✵ ⠦ ✺",
    "⋆ ⠧ ✵",
    "✧ ⠇ ⋆",
    "✦ ⠏ ✧",
] if USE_UNICODE else ["[ * . . ]", "[ . * . ]", "[ . . * ]", "[ . * . ]"]

ASTRA_PULSE_FRAMES = [
    "⟨ ✦ · · · · ⟩",
    "⟨ · ✧ · · · ⟩",
    "⟨ · · ⋆ · · ⟩",
    "⟨ · · · ✵ · ⟩",
    "⟨ · · · · ✦ ⟩",
    "⟨ · · · ✵ · ⟩",
    "⟨ · · ⋆ · · ⟩",
    "⟨ · ✧ · · · ⟩",
] if USE_UNICODE else ["<*...>", "<.*..>", "<..*.>", "<...*>"]

ASTRA_ORBIT_FRAMES = [
    "⠋ ✦ ⋆",
    "⠙ ⋆ ✦",
    "⠹ ✧ ⋆",
    "⠸ ✦ ✧",
    "⠼ ⋆ ✦",
    "⠴ ✧ ⋆",
    "⠦ ✦ ✧",
    "⠧ ⋆ ✦",
    "⠇ ✧ ⋆",
    "⠏ ✦ ✧",
] if USE_UNICODE else ["[ ✦ ]", "[ ✧ ]", "[ ⋆ ]", "[ ✦ ]"]

SPINNERS["astra"] = {
    "interval": 80,
    "frames": ASTRA_SPINNER_FRAMES,
}

SPINNERS["astra_pulse"] = {
    "interval": 80,
    "frames": ASTRA_PULSE_FRAMES,
}

SPINNERS["astra_orbit"] = {
    "interval": 80,
    "frames": ASTRA_ORBIT_FRAMES,
}


class AstraLoader:
    """Creative cosmic loader for AstraRecon with astral glyphs and telemetry updates."""

    def __init__(
        self,
        message: str = "Aligning constellation telemetry...",
        console: Optional[Console] = None,
        spinner: str = "astra",
        transient: bool = True,
    ):
        self.message = message
        self.console = console or Console(legacy_windows=False)
        self.spinner = spinner
        self.transient = transient
        self._status = None

        # Only activate animations if interactive TTY and not opted out
        opt_out = os.environ.get("ASTRARECON_NO_LOADER", "").lower() in ("1", "true", "yes")
        is_tty = sys.stdin.isatty() and sys.stdout.isatty()
        self._enabled = is_tty and not opt_out

    def _format_status(self, msg: str) -> str:
        prefix = f"[bold white]ASTRA[/bold white][bold {COLOR_ACCENT}]RECON[/bold {COLOR_ACCENT}]"
        return f"{prefix} [dim]─ {msg}[/dim]"

    def update(self, message: str) -> None:
        """Update the status message dynamically with smooth transition."""
        self.message = message
        if self._status:
            self._status.update(self._format_status(message))

    def __enter__(self) -> "AstraLoader":
        if self._enabled:
            self._status = self.console.status(
                self._format_status(self.message),
                spinner=self.spinner,
                spinner_style=f"bold {COLOR_ACCENT}",
                speed=1.0,
            )
            self._status.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._status:
            self._status.stop()
            self._status = None


def astra_loader(
    message: str = "Aligning constellation telemetry...",
    console: Optional[Console] = None,
    spinner: str = "astra",
    transient: bool = True,
) -> AstraLoader:
    """Convenience factory function for AstraLoader."""
    return AstraLoader(message=message, console=console, spinner=spinner, transient=transient)
