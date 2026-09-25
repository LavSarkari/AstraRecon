"""Update CLI: Self-update AstraRecon from PyPI or GitHub."""

from __future__ import annotations

import subprocess
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from astrarecon import __version__
from astrarecon.cli.ui.theme import (
    COLOR_ACCENT,
    COLOR_DIVIDER,
    COLOR_ERROR,
    COLOR_PRIMARY,
    COLOR_SECONDARY,
    COLOR_SUCCESS,
    COLOR_WARNING,
    PANEL_BOX,
)

app = typer.Typer(invoke_without_command=True, help="Update AstraRecon to the latest version.")
console = Console(legacy_windows=False)

_PYPI_API = "https://pypi.org/pypi/astrarecon/json"
_GITHUB_REPO = "LavSarkari/AstraRecon"
_GITHUB_BRANCH = "main"


def _fetch_latest_pypi_version() -> Optional[str]:
    """Returns the latest version string from PyPI, or None on failure."""
    try:
        import urllib.request, json
        with urllib.request.urlopen(_PYPI_API, timeout=8) as resp:
            data = json.loads(resp.read())
            return data["info"]["version"]
    except Exception:
        return None


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


@app.callback(invoke_without_command=True)
def update(
    ctx: typer.Context,
    source: str = typer.Option(
        "pypi",
        "--source",
        "-s",
        help="Update source: 'pypi' (stable release) or 'github' (latest commit on main)",
    ),
    check: bool = typer.Option(
        False,
        "--check",
        "-c",
        help="Only check for updates, do not install.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force reinstall even if already on the latest version.",
    ),
):
    """Check for and apply updates to AstraRecon.

    Examples:

        astrarecon update               # Update from PyPI (stable)

        astrarecon update --check       # Just check, don't install

        astrarecon update --source github   # Install latest commit from GitHub
    """
    if ctx.invoked_subcommand is not None:
        return

    console.print()
    console.print(Rule(
        title=f"[bold {COLOR_ACCENT}]  ASTRARECON UPDATE  [/bold {COLOR_ACCENT}]",
        style=COLOR_DIVIDER,
    ))
    console.print()

    current = __version__
    console.print(f"  Current version  [bold {COLOR_PRIMARY}]{current}[/bold {COLOR_PRIMARY}]")

    # -----------------------------------------------------------------------
    # GitHub source
    # -----------------------------------------------------------------------
    if source == "github":
        console.print(f"  Source           [bold {COLOR_ACCENT}]GitHub ({_GITHUB_REPO}@{_GITHUB_BRANCH})[/bold {COLOR_ACCENT}]\n")

        if check:
            console.print(f"  [dim]Use --source github without --check to install from GitHub.[/dim]\n")
            return

        install_target = f"git+https://github.com/{_GITHUB_REPO}.git@{_GITHUB_BRANCH}"
        console.print(f"  [dim]Installing from GitHub…[/dim]\n")

        try:
            result = _run([sys.executable, "-m", "pip", "install", "--upgrade", install_target])
            console.print(f"  [{COLOR_SUCCESS}]✔[/{COLOR_SUCCESS}] Updated from GitHub main branch.\n")
            if result.stdout:
                for line in result.stdout.strip().splitlines()[-5:]:
                    console.print(f"  [dim]{line}[/dim]")
        except subprocess.CalledProcessError as e:
            console.print(f"\n  [bold {COLOR_ERROR}]✖ Update failed:[/bold {COLOR_ERROR}] pip returned exit code {e.returncode}")
            if e.stderr:
                for line in e.stderr.strip().splitlines()[-8:]:
                    console.print(f"  [dim {COLOR_ERROR}]{line}[/dim {COLOR_ERROR}]")
            raise typer.Exit(code=1)

        console.print()
        return

    # -----------------------------------------------------------------------
    # PyPI source (default)
    # -----------------------------------------------------------------------
    console.print(f"  Source           [bold {COLOR_ACCENT}]PyPI (stable)[/bold {COLOR_ACCENT}]")
    console.print(f"  [dim]Checking PyPI for latest version…[/dim]")

    latest = _fetch_latest_pypi_version()

    if latest is None:
        console.print(f"\n  [bold {COLOR_WARNING}]⚠ Could not reach PyPI.[/bold {COLOR_WARNING}] Check your internet connection.\n")
        raise typer.Exit(code=1)

    console.print(f"  Latest version   [bold {COLOR_SUCCESS}]{latest}[/bold {COLOR_SUCCESS}]\n")

    # Version comparison
    def _parse(v: str) -> tuple[int, ...]:
        try:
            return tuple(int(x) for x in v.strip().split("."))
        except Exception:
            return (0,)

    current_t = _parse(current)
    latest_t = _parse(latest)

    if latest_t <= current_t and not force:
        console.print(
            f"  [{COLOR_SUCCESS}]✔[/{COLOR_SUCCESS}] You are already on the latest version "
            f"[bold {COLOR_SUCCESS}]{current}[/bold {COLOR_SUCCESS}].\n"
        )
        console.print(
            f"  [dim]Use [bold]--force[/bold] to reinstall anyway, "
            f"or [bold]--source github[/bold] for the bleeding-edge build.[/dim]\n"
        )
        return

    if latest_t > current_t:
        delta = Text()
        delta.append(f"  Update available: ", style=f"bold {COLOR_WARNING}")
        delta.append(f"{current}", style=f"dim {COLOR_SECONDARY}")
        delta.append(f"  →  ", style=f"dim {COLOR_SECONDARY}")
        delta.append(f"{latest}", style=f"bold {COLOR_SUCCESS}")
        console.print(delta)

    if check:
        if latest_t > current_t:
            console.print(f"\n  Run [bold {COLOR_ACCENT}]astrarecon update[/bold {COLOR_ACCENT}] to install.\n")
        return

    console.print(f"\n  [dim]Installing astrarecon=={latest} from PyPI…[/dim]\n")

    try:
        cmd = [sys.executable, "-m", "pip", "install", "--upgrade", f"astrarecon=={latest}"]
        if force and latest_t <= current_t:
            cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall", f"astrarecon=={latest}"]

        result = _run(cmd)
        console.print(f"  [{COLOR_SUCCESS}]✔[/{COLOR_SUCCESS}] Updated to [bold {COLOR_SUCCESS}]{latest}[/bold {COLOR_SUCCESS}] successfully.\n")
        console.print(
            f"  [dim]Restart your shell or run [bold]hash -r[/bold] if the command is cached.[/dim]\n"
        )
        if result.stdout:
            for line in result.stdout.strip().splitlines()[-4:]:
                console.print(f"  [dim]{line}[/dim]")

    except subprocess.CalledProcessError as e:
        console.print(f"\n  [bold {COLOR_ERROR}]✖ Update failed:[/bold {COLOR_ERROR}] pip returned exit code {e.returncode}")
        if e.stderr:
            for line in e.stderr.strip().splitlines()[-8:]:
                console.print(f"  [dim {COLOR_ERROR}]{line}[/dim {COLOR_ERROR}]")
        console.print(
            f"\n  [dim]Try manually: [bold]pip install --upgrade astrarecon[/bold][/dim]\n"
        )
        raise typer.Exit(code=1)

    console.print()
