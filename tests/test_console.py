"""Unit tests for the interactive reconnaissance console."""

import pytest
from astrarecon.cli.console import (
    ConsoleState,
    build_completer,
    render_banner,
    render_help,
    show_options,
    show_workflows,
)


def test_console_state_options():
    """Verify state initialization, setting, and unsetting options."""
    state = ConsoleState()
    assert state.options["TARGET"] == ""
    assert state.options["WORKFLOW"] == "default"
    assert state.active_module == "workflow/default"

    # Set target
    assert state.set_option("target", "example.com")
    assert state.options["TARGET"] == "example.com"

    # Set proxy
    assert state.set_option("proxy", "http://127.0.0.1:8080")
    assert state.options["PROXY"] == "http://127.0.0.1:8080"

    # Change workflow updates active module
    assert state.set_option("workflow", "fast")
    assert state.options["WORKFLOW"] == "fast"
    assert state.active_module == "workflow/fast"

    # Unset option
    assert state.unset_option("proxy")
    assert state.options["PROXY"] == ""

    # Invalid option returns False
    assert not state.set_option("NON_EXISTENT", "value")


def test_console_renders_without_errors():
    """Verify banner, options table, workflow table, and help render cleanly."""
    state = ConsoleState()
    state.set_option("TARGET", "example.com")

    # These should execute cleanly without raising exceptions
    render_banner()
    show_options(state)
    show_workflows()
    render_help()


def test_console_completer():
    """Verify NestedCompleter compiles with all core commands and options."""
    completer = build_completer()
    assert completer is not None


def test_execute_scan_args_parsing():
    """Verify inline args passed to scan/run update target and flags."""
    from unittest.mock import patch
    from astrarecon.cli.console import execute_scan

    state = ConsoleState()
    with patch("astrarecon.cli.scan.run_scan") as mock_scan:
        execute_scan(state, ["example.com", "--workflow", "fast", "--proxy", "http://127.0.0.1:8080"])
        assert state.options["TARGET"] == "example.com"
        assert state.options["WORKFLOW"] == "fast"
        assert state.options["PROXY"] == "http://127.0.0.1:8080"
        assert mock_scan.called
