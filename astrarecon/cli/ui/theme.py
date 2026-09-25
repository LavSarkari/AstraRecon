"""AstraRecon CLI Theme, Color Tokens, and Status Icons."""

import sys
from rich.box import ROUNDED
from rich.style import Style
from rich.theme import Theme

# Hex Color Palette (Design Specification)
COLOR_BG = "#000000"
COLOR_PRIMARY = "#F8FAFC"
COLOR_SECONDARY = "#94A3B8"
COLOR_ACCENT = "#1DA1FF"
COLOR_DIVIDER = "#1E293B"
COLOR_SUCCESS = "#22C55E"
COLOR_WARNING = "#F59E0B"
COLOR_ERROR = "#EF4444"

# Rich Styles
STYLE_PRIMARY = Style(color=COLOR_PRIMARY)
STYLE_SECONDARY = Style(color=COLOR_SECONDARY)
STYLE_ACCENT = Style(color=COLOR_ACCENT, bold=True)
STYLE_DIVIDER = Style(color=COLOR_DIVIDER)
STYLE_SUCCESS = Style(color=COLOR_SUCCESS)
STYLE_WARNING = Style(color=COLOR_WARNING)
STYLE_ERROR = Style(color=COLOR_ERROR)
STYLE_MUTED = Style(color=COLOR_SECONDARY, dim=True)

# Standard Rounded Box
PANEL_BOX = ROUNDED

# Unicode Support Detection: Linux/WSL/UTF-8 terminals get full unicode glyphs
USE_UNICODE = "utf" in (sys.stdout.encoding or "").lower() or sys.platform != "win32"

# Status Icons Table as specified:
# Running: ▶, Waiting: ●, Success: ✔, Retry: ↻, Failed: ✖, Cached: ◈, Skipped: ○
STATUS_ICONS = {
    "RUNNING": ("▶" if USE_UNICODE else ">", COLOR_ACCENT),
    "WAITING": ("●" if USE_UNICODE else "o", COLOR_SECONDARY),
    "SUCCESS": ("✔" if USE_UNICODE else "[OK]", COLOR_SUCCESS),
    "COMPLETED": ("✔" if USE_UNICODE else "[OK]", COLOR_SUCCESS),
    "RETRY": ("↻" if USE_UNICODE else "R", COLOR_WARNING),
    "FAILED": ("✖" if USE_UNICODE else "[X]", COLOR_ERROR),
    "CACHED": ("◈" if USE_UNICODE else "*", COLOR_ACCENT),
    "SKIPPED": ("○" if USE_UNICODE else "-", COLOR_SECONDARY),
}

# Icon glyphs
CHECK_ICON = "✓" if USE_UNICODE else "[OK]"
BULLET_ICON = "•" if USE_UNICODE else "|"
DIVIDER_CHAR = "─" if USE_UNICODE else "-"
SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"] if USE_UNICODE else [">", ">>", ">>>", ">"]

ASTRA_THEME = Theme({
    "primary": COLOR_PRIMARY,
    "secondary": COLOR_SECONDARY,
    "accent": COLOR_ACCENT,
    "divider": COLOR_DIVIDER,
    "success": COLOR_SUCCESS,
    "warning": COLOR_WARNING,
    "error": COLOR_ERROR,
})
