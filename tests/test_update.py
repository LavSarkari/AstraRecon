"""Unit tests for AstraRecon update checker and version comparison."""

import pytest
import sys
from unittest.mock import patch, MagicMock

from astrarecon.cli.update import _parse, check_and_prompt_update


from pathlib import Path

def test_parse_version():
    """Verify version parsing and semantic ordering."""
    assert _parse("0.1.0") < _parse("0.2.0")
    assert _parse("0.2.0") == (0, 2, 0)
    assert _parse("v0.2.0") == (0, 2, 0)
    assert _parse("v0.2.1-dev") == (0, 2, 1)
    assert _parse("invalid") == (0,)


def test_check_and_prompt_update_skips_non_tty(monkeypatch):
    """Update check must skip silently if stdin is not a TTY (piped/scripted)."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys, "argv", ["astrarecon", "scan", "example.com"])
    # Should return cleanly without any prompt
    check_and_prompt_update()


def test_check_and_prompt_update_skips_when_opted_out(monkeypatch):
    """Update check must skip when ASTRARECON_NO_UPDATE_CHECK=1."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setenv("ASTRARECON_NO_UPDATE_CHECK", "1")
    monkeypatch.setattr(sys, "argv", ["astrarecon", "scan", "example.com"])
    check_and_prompt_update()


def test_check_and_prompt_update_skips_on_update_subcommand(monkeypatch):
    """Update check must skip when already running the update subcommand."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.delenv("ASTRARECON_NO_UPDATE_CHECK", raising=False)
    monkeypatch.setattr(sys, "argv", ["astrarecon", "update"])
    with patch("astrarecon.cli.update._fetch_latest_github_version") as mock_fetch:
        check_and_prompt_update()
        assert not mock_fetch.called


def test_check_and_prompt_update_skips_on_version_flag(monkeypatch):
    """Update check must skip when running with --version or standalone -v."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.delenv("ASTRARECON_NO_UPDATE_CHECK", raising=False)
    monkeypatch.setattr(sys, "argv", ["astrarecon", "--version"])
    with patch("astrarecon.cli.update._fetch_latest_github_version") as mock_fetch:
        check_and_prompt_update()
        assert not mock_fetch.called


def test_check_and_prompt_update_prompts_when_newer_available(monkeypatch, tmp_path):
    """Verify notification and prompt when a newer version exists."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.delenv("ASTRARECON_NO_UPDATE_CHECK", raising=False)
    monkeypatch.setattr(sys, "argv", ["astrarecon", "scan", "example.com"])
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    with patch("astrarecon.cli.update._fetch_latest_github_version", return_value="9.9.9"):
        with patch("typer.confirm", return_value=False) as mock_confirm:
            check_and_prompt_update()
            assert mock_confirm.called

