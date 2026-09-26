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


def _parse(v: str) -> tuple[int, ...]:
    """Parse version string into integer tuple for comparison."""
    try:
        clean = v.strip().lstrip("v").split("-")[0]
        return tuple(int(x) for x in clean.split("."))
    except Exception:
        return (0,)


def _fetch_latest_pypi_version() -> Optional[str]:
    """Returns the latest version string from PyPI, or None on failure."""
    try:
        import urllib.request, json
        with urllib.request.urlopen(_PYPI_API, timeout=8) as resp:
            data = json.loads(resp.read())
            return data["info"]["version"]
    except Exception:
        return None


def _fetch_latest_github_version() -> Optional[str]:
    """Fetches the latest version string from GitHub main branch with 1.5s timeout."""
    try:
        import urllib.request, re
        url = f"https://raw.githubusercontent.com/{_GITHUB_REPO}/{_GITHUB_BRANCH}/astrarecon/__init__.py"
        req = urllib.request.Request(url, headers={"User-Agent": "AstraRecon-Updater"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            content = resp.read().decode("utf-8")
            m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
            if m:
                return m.group(1).strip()
    except Exception:
        pass
    return None


def check_and_prompt_update() -> None:
    """Pre-execution update checker: checks if a newer version is available and prompts user."""
    import os, time, json
    from pathlib import Path

    # Only run in interactive terminals
    if not sys.stdin.isatty():
        return

    # Check opt-out flags
    if os.environ.get("ASTRARECON_NO_UPDATE_CHECK", "").lower() in ("1", "true", "yes"):
        return

    # Skip if running update, help, or version command, or opt-out flag passed
    argv = sys.argv[1:]
    if argv and argv[0] == "update":
        return
    if "--no-update-check" in argv:
        return
    if "--version" in argv or argv == ["-v"]:
        return
    if "--help" in argv or "-h" in argv:
        return

    cache_file = Path.home() / ".astrarecon" / "update_check.json"
    cache_data = {}
    now = time.time()

    if cache_file.exists():
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cache_data = json.load(f)
        except Exception:
            cache_data = {}

    last_check = cache_data.get("last_check", 0)
    cached_version = cache_data.get("latest_version")
    cached_source = cache_data.get("source", "github")

    latest = None
    source = "github"

    # Cache check for 10 minutes to maintain snappy startup
    if now - last_check < 600 and cached_version:
        latest = cached_version
        source = cached_source
    else:
        from astrarecon.cli.ui.loader import AstraLoader

        with AstraLoader("Querying cosmic update relay..."):
            # Check GitHub main first, fallback to PyPI
            latest = _fetch_latest_github_version()
            if latest:
                source = "github"
            else:
                latest = _fetch_latest_pypi_version()
                source = "pypi"

        if latest:
            try:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump({"last_check": now, "latest_version": latest, "source": source}, f)
            except Exception:
                pass

    if not latest:
        return

    current = __version__
    if _parse(latest) <= _parse(current):
        return

    # An update is available!
    console.print()
    update_panel = Panel(
        Text.from_markup(
            f"[bold {COLOR_WARNING}]⚡ A new version of AstraRecon is available![/bold {COLOR_WARNING}]\n\n"
            f"   Current version: [bold {COLOR_PRIMARY}]v{current}[/bold {COLOR_PRIMARY}]\n"
            f"   Latest version:  [bold {COLOR_SUCCESS}]v{latest}[/bold {COLOR_SUCCESS}]  ([dim]{source}[/dim])\n"
        ),
        title=f"[bold white]ASTRA[/bold white][bold {COLOR_PRIMARY}]RECON[/bold {COLOR_PRIMARY}] [dim]─ Update Available[/dim]",
        title_align="left",
        box=PANEL_BOX,
        border_style=COLOR_DIVIDER,
        padding=(0, 2),
    )
    console.print(update_panel)

    try:
        choice = typer.confirm("Would you like to update AstraRecon now?", default=False)
    except Exception:
        return

    if choice:
        console.print(f"\n[dim]Installing latest version (v{latest})…[/dim]\n")
        install_target = f"git+https://github.com/{_GITHUB_REPO}.git@{_GITHUB_BRANCH}" if source == "github" else f"astrarecon=={latest}"
        try:
            _run_install(install_target, force=True)
            console.print(f"\n[bold {COLOR_SUCCESS}]✔ Successfully updated to v{latest}![/bold {COLOR_SUCCESS}]")
            console.print(f"[dim]Please re-run your command to use the updated version.[/dim]\n")
            try:
                cache_file.unlink(missing_ok=True)
            except Exception:
                pass
            raise typer.Exit(code=0)
        except subprocess.CalledProcessError as e:
            console.print(f"\n[bold {COLOR_ERROR}]✖ Update failed:[/bold {COLOR_ERROR}] {e}")
            console.print("[dim]Continuing with current version…[/dim]\n")
    else:
        console.print("[dim]Continuing without updating…[/dim]\n")


import shutil


def _run_install(install_target: str, force: bool = False) -> subprocess.CompletedProcess:
    """Executes the package installation using uv, pipx, or pip depending on the environment."""
    uv_bin = shutil.which("uv")
    pipx_bin = shutil.which("pipx")

    # If installed via uv tool or uv environment
    if "uv/tools" in sys.executable.replace("\\", "/") and uv_bin:
        cmd = [uv_bin, "tool", "install", install_target, "--reinstall"]
        return _run(cmd)

    if uv_bin:
        cmd = [uv_bin, "pip", "install", "--python", sys.executable, "--upgrade", install_target]
        if force:
            cmd.append("--reinstall")
        return _run(cmd)

    # If pipx environment
    if "pipx" in sys.executable.lower() and pipx_bin:
        cmd = [pipx_bin, "install", "--force", install_target]
        return _run(cmd)

    # Standard pip fallback
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", install_target]
    if force:
        cmd.append("--force-reinstall")
    return _run(cmd)


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def run_update(
    source: str = "pypi",
    check: bool = False,
    force: bool = False,
) -> None:
    """Core update executor that checks or applies updates from GitHub or PyPI."""
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
        from astrarecon.cli.ui.loader import AstraLoader

        try:
            with AstraLoader("Installing update from GitHub repository..."):
                result = _run_install(install_target, force=force)
            console.print(f"  [{COLOR_SUCCESS}]✔[/{COLOR_SUCCESS}] Updated from GitHub main branch.\n")
            if result.stdout:
                for line in result.stdout.strip().splitlines()[-5:]:
                    console.print(f"  [dim]{line}[/dim]")
        except subprocess.CalledProcessError as e:
            console.print(f"\n  [bold {COLOR_ERROR}]✖ Update failed:[/bold {COLOR_ERROR}] installer returned exit code {e.returncode}")
            if e.stderr:
                for line in e.stderr.strip().splitlines()[-8:]:
                    console.print(f"  [dim {COLOR_ERROR}]{line}[/dim {COLOR_ERROR}]")
            raise typer.Exit(code=1)

        console.print()
        return

    # -----------------------------------------------------------------------
    # PyPI source (default)
    # -----------------------------------------------------------------------
    from astrarecon.cli.ui.loader import AstraLoader

    console.print(f"  Source           [bold {COLOR_ACCENT}]PyPI (stable)[/bold {COLOR_ACCENT}]")

    with AstraLoader("Checking PyPI for latest release..."):
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

    try:
        with AstraLoader(f"Installing astrarecon=={latest} from PyPI..."):
            result = _run_install(f"astrarecon=={latest}", force=force and latest_t <= current_t)
        console.print(f"  [{COLOR_SUCCESS}]✔[/{COLOR_SUCCESS}] Updated to [bold {COLOR_SUCCESS}]{latest}[/bold {COLOR_SUCCESS}] successfully.\n")
        console.print(
            f"  [dim]Restart your shell or run [bold]hash -r[/bold] if the command is cached.[/dim]\n"
        )
        if result.stdout:
            for line in result.stdout.strip().splitlines()[-4:]:
                console.print(f"  [dim]{line}[/dim]")

    except subprocess.CalledProcessError as e:
        console.print(f"\n  [bold {COLOR_ERROR}]✖ Update failed:[/bold {COLOR_ERROR}] installer returned exit code {e.returncode}")
        if e.stderr:
            for line in e.stderr.strip().splitlines()[-8:]:
                console.print(f"  [dim {COLOR_ERROR}]{line}[/dim {COLOR_ERROR}]")
        console.print(
            f"\n  [dim]Try manually: [bold]uv tool install astrarecon --reinstall[/bold] or [bold]pip install --upgrade astrarecon[/bold][/dim]\n"
        )
        raise typer.Exit(code=1)

    console.print()


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
    run_update(source=source, check=check, force=force)
