"""Unit tests for AstraRecon creative cosmic UI loader."""

import sys
from rich.console import Console
from rich._spinners import SPINNERS

from astrarecon.cli.ui.loader import AstraLoader, astra_loader


def test_custom_spinners_registered():
    """Verify that celestial Astra spinners are registered into rich._spinners.SPINNERS."""
    assert "astra" in SPINNERS
    assert "astra_pulse" in SPINNERS
    assert "astra_orbit" in SPINNERS

    assert len(SPINNERS["astra"]["frames"]) > 0
    assert len(SPINNERS["astra_pulse"]["frames"]) > 0
    assert len(SPINNERS["astra_orbit"]["frames"]) > 0


def test_astra_loader_lifecycle(monkeypatch):
    """Verify clean context manager enter and exit."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.delenv("ASTRARECON_NO_LOADER", raising=False)

    con = Console(record=True)
    with AstraLoader("Aligning constellation telemetry...", console=con) as loader:
        assert loader.message == "Aligning constellation telemetry..."
        loader.update("Inspecting orbital tool binaries...")
        assert loader.message == "Inspecting orbital tool binaries..."


def test_astra_loader_skips_when_opted_out(monkeypatch):
    """Verify loader remains disabled when ASTRARECON_NO_LOADER=1."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setenv("ASTRARECON_NO_LOADER", "1")

    loader = AstraLoader("Test message")
    assert not loader._enabled


def test_astra_loader_skips_when_non_tty(monkeypatch):
    """Verify loader is safely disabled in non-interactive environments (CI, pipes)."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    loader = AstraLoader("Non-tty message")
    assert not loader._enabled


def test_astra_loader_convenience_factory():
    """Verify helper astra_loader() instantiates properly."""
    loader = astra_loader("Quick test")
    assert isinstance(loader, AstraLoader)
    assert loader.message == "Quick test"
