"""Automated Security Tool Installer.

Downloads official pre-compiled binaries from GitHub releases or compiles
via `go install` into the managed directory ~/.astrarecon/bin/.
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional

from rich.console import Console

from astrarecon.core.doctor.inspector import EnvironmentInspector


class ToolInstaller:
    """Automates downloading and compiling core security tools."""

    TOOL_CATALOG = {
        "subfinder": {
            "go_pkg": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "github_repo": "projectdiscovery/subfinder",
            "binary_name": "subfinder",
        },
        "assetfinder": {
            "go_pkg": "github.com/tomnomnom/assetfinder@latest",
            "github_repo": "tomnomnom/assetfinder",
            "binary_name": "assetfinder",
        },
        "amass": {
            "go_pkg": "github.com/owasp-amass/amass/v3/...@latest",
            "github_repo": "owasp-amass/amass",
            "binary_name": "amass",
        },
        "dnsx": {
            "go_pkg": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "github_repo": "projectdiscovery/dnsx",
            "binary_name": "dnsx",
        },
        "httpx": {
            "go_pkg": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "github_repo": "projectdiscovery/httpx",
            "binary_name": "httpx",
        },
        "naabu": {
            "go_pkg": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "github_repo": "projectdiscovery/naabu",
            "binary_name": "naabu",
        },
        "katana": {
            "go_pkg": "github.com/projectdiscovery/katana/cmd/katana@latest",
            "github_repo": "projectdiscovery/katana",
            "binary_name": "katana",
        },
        "nuclei": {
            "go_pkg": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "github_repo": "projectdiscovery/nuclei",
            "binary_name": "nuclei",
        },
        "dalfox": {
            "go_pkg": "github.com/hahwul/dalfox/v2@latest",
            "github_repo": "hahwul/dalfox",
            "binary_name": "dalfox",
        },
        "gau": {
            "go_pkg": "github.com/lc/gau/v2/cmd/gau@latest",
            "github_repo": "lc/gau",
            "binary_name": "gau",
        },
        "waybackurls": {
            "go_pkg": "github.com/tomnomnom/waybackurls@latest",
            "github_repo": "tomnomnom/waybackurls",
            "binary_name": "waybackurls",
        },
        "linkfinder": {
            "python_git": "https://github.com/GerbenJavado/LinkFinder.git",
            "python_entry": "linkfinder.py",       # main script inside the repo
            "pip_requirements": "requirements.txt",  # pip install -r this file if present
            "binary_name": "linkfinder",
        },
        "subenum": {
            "raw_url": "https://raw.githubusercontent.com/bing0o/SubEnum/master/subenum.sh",
            "binary_name": "subenum",
        },
    }

    @classmethod
    def get_target_dir(cls) -> Path:
        """Returns the managed destination directory ~/.astrarecon/bin."""
        target_dir = EnvironmentInspector.get_managed_bin_dir()
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    @classmethod
    def install_tool(cls, tool_name: str) -> tuple[bool, str]:
        """Installs a single tool using go install or precompiled GitHub release.
        
        Returns (success: bool, detail_message: str).
        """
        if tool_name not in cls.TOOL_CATALOG:
            return False, f"Unknown tool '{tool_name}'"

        target_dir = cls.get_target_dir()
        meta = cls.TOOL_CATALOG[tool_name]
        bin_name = meta["binary_name"]
        bin_ext = ".exe" if sys.platform == "win32" else ""
        expected_bin = target_dir / f"{bin_name}{bin_ext}"

        # Strategy 0: Direct script download for bash tools (e.g. subenum)
        if meta.get("raw_url"):
            try:
                dest = target_dir / bin_name
                req = urllib.request.Request(meta["raw_url"], headers={"User-Agent": "AstraRecon/1.0"})
                with urllib.request.urlopen(req, timeout=15) as resp, open(dest, "wb") as f:
                    shutil.copyfileobj(resp, f)
                if sys.platform != "win32":
                    os.chmod(dest, 0o755)
                else:
                    bat_path = target_dir / f"{bin_name}.bat"
                    bat_path.write_text(f"@echo off\r\nwsl -e ~/.astrarecon/bin/{bin_name} %*\r\n")
                return True, "Downloaded official subenum.sh script"
            except Exception as e:
                return False, f"Script download failed: {e}"

        # Strategy 0.5: Clone Python tool from Git and create a wrapper script
        if meta.get("python_git"):
            return cls._install_python_git_tool(
                git_url=meta["python_git"],
                entry_script=meta.get("python_entry", f"{bin_name}.py"),
                requirements_file=meta.get("pip_requirements", "requirements.txt"),
                bin_name=bin_name,
                target_dir=target_dir,
            )

        # Strategy 1: Download official precompiled release from GitHub (fastest, pre-built)
        if meta.get("github_repo"):
            success, msg = cls._install_via_github_release(meta["github_repo"], bin_name, target_dir, expected_bin)
            if success:
                return True, msg

        # Strategy 2: Compile via Go if available and release was not found
        go_path = shutil.which("go")
        if go_path and meta.get("go_pkg"):
            success, msg = cls._install_via_go(go_path, meta["go_pkg"], target_dir, expected_bin)
            if success:
                return True, msg

        # Strategy 3: On Windows without Go, check if WSL has Go and cross-compile!
        if sys.platform == "win32" and meta.get("go_pkg"):
            wsl_path = shutil.which("wsl")
            if wsl_path:
                try:
                    # Resolve Windows path to /mnt/c/...
                    resolved = expected_bin.resolve()
                    drive = resolved.drive.replace(":", "").lower()
                    rest = str(resolved)[2:].replace("\\", "/")
                    wsl_dest = f"/mnt/{drive}{rest}"
                    wsl_cmd = (
                        f"GOOS=windows GOARCH=amd64 go install {meta['go_pkg']} && "
                        f"cp $(go env GOPATH)/bin/windows_amd64/{expected_bin.name} '{wsl_dest}'"
                    )
                    res = subprocess.run([wsl_path, "-e", "bash", "-c", wsl_cmd], capture_output=True, text=True, timeout=120)
                    if expected_bin.is_file():
                        return True, f"Cross-compiled via WSL Go ({expected_bin.name})"
                except Exception:
                    pass

        return False, "Failed to compile via Go or download GitHub release archive."

    @classmethod
    def _install_via_go(
        cls,
        go_path: str,
        package_url: str,
        target_dir: Path,
        expected_bin: Path,
    ) -> tuple[bool, str]:
        """Installs a tool binary using go install with GOBIN set to target_dir."""
        env = os.environ.copy()
        env["GOBIN"] = str(target_dir)

        try:
            res = subprocess.run(
                [go_path, "install", package_url],
                env=env,
                capture_output=True,
                text=True,
                timeout=180,
            )
            if expected_bin.is_file():
                if sys.platform != "win32":
                    os.chmod(expected_bin, 0o755)
                return True, f"Compiled via Go ({expected_bin.name})"
            elif res.returncode == 0:
                # Binary might have been installed without .exe or with a variant name
                for candidate in target_dir.glob(f"{expected_bin.stem}*"):
                    if candidate.is_file():
                        if sys.platform != "win32":
                            os.chmod(candidate, 0o755)
                        return True, f"Compiled via Go ({candidate.name})"
        except Exception as e:
            return False, f"Go compilation error: {e}"

        return False, "go install did not produce target executable"

    @classmethod
    def _install_python_git_tool(
        cls,
        git_url: str,
        entry_script: str,
        requirements_file: str,
        bin_name: str,
        target_dir: Path,
    ) -> tuple[bool, str]:
        """Clones a Python-based tool from Git, installs its deps, and writes a wrapper script.

        Layout after install:
            ~/.astrarecon/tools/<bin_name>/  ← git clone destination
            ~/.astrarecon/bin/<bin_name>     ← executable wrapper script
        """
        tools_dir = target_dir.parent / "tools"
        tools_dir.mkdir(parents=True, exist_ok=True)
        clone_dest = tools_dir / bin_name

        # Check git is available
        git_exe = shutil.which("git")
        if not git_exe:
            return False, "git not found in PATH — cannot clone repository"

        # Clone or update
        try:
            if clone_dest.exists():
                res = subprocess.run(
                    [git_exe, "-C", str(clone_dest), "pull", "--ff-only"],
                    capture_output=True, text=True, timeout=60,
                )
            else:
                res = subprocess.run(
                    [git_exe, "clone", "--depth=1", git_url, str(clone_dest)],
                    capture_output=True, text=True, timeout=120,
                )
            if res.returncode != 0:
                return False, f"git clone/pull failed: {res.stderr.strip()[:200]}"
        except Exception as e:
            return False, f"git error: {e}"

        # Locate the entry script
        entry_path = clone_dest / entry_script
        if not entry_path.exists():
            matches = list(clone_dest.rglob(entry_script))
            if matches:
                entry_path = matches[0]
            else:
                return False, f"Entry script '{entry_script}' not found after clone"

        # Install pip requirements (non-fatal if it fails)
        req_file = clone_dest / requirements_file
        python_exe = sys.executable
        if req_file.exists():
            try:
                subprocess.run(
                    [python_exe, "-m", "pip", "install", "-r", str(req_file), "--quiet"],
                    capture_output=True, text=True, timeout=120, check=True,
                )
            except subprocess.CalledProcessError:
                pass  # wrapper will surface dep errors at runtime

        # Write an executable bash wrapper
        wrapper = target_dir / bin_name
        wrapper.write_text(
            f"#!/usr/bin/env bash\n"
            f"# AstraRecon-managed wrapper for {bin_name}\n"
            f"exec {python_exe} '{entry_path}' \"$@\"\n",
            encoding="utf-8",
        )
        os.chmod(wrapper, 0o755)

        return True, f"Cloned from GitHub + wrapper written ({entry_path.name})"

    @classmethod
    def _install_via_github_release(
        cls,
        github_repo: str,
        bin_name: str,
        target_dir: Path,
        expected_bin: Path,
    ) -> tuple[bool, str]:
        """Downloads the latest matching binary from official GitHub releases."""
        # Detect host OS & architecture
        plat = sys.platform
        arch = platform.machine().lower()

        if plat == "linux":
            os_match = "linux"
        elif plat == "win32":
            os_match = "windows"
        elif plat == "darwin":
            os_match = "macOS" if "macOS" in platform.platform() else "darwin"
        else:
            os_match = plat

        if arch in ("x86_64", "amd64"):
            arch_match = "amd64"
        elif arch in ("aarch64", "arm64"):
            arch_match = "arm64"
        elif "386" in arch or "686" in arch:
            arch_match = "386"
        else:
            arch_match = "amd64"

        api_url = f"https://api.github.com/repos/{github_repo}/releases/latest"
        headers = {"User-Agent": "AstraRecon-Tool-Installer/1.0"}

        try:
            req = urllib.request.Request(api_url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            assets = data.get("assets", [])
            download_url = None
            archive_name = None

            for asset in assets:
                name = asset.get("name", "").lower()
                # Check OS and Architecture in asset filename
                if os_match in name and arch_match in name:
                    if name.endswith((".zip", ".tar.gz", ".tgz")):
                        download_url = asset.get("browser_download_url")
                        archive_name = asset.get("name")
                        break

            # Fallback check if architecture pattern was slightly different (e.g. x86_64)
            if not download_url and arch_match == "amd64":
                for asset in assets:
                    name = asset.get("name", "").lower()
                    if os_match in name and ("x86_64" in name or "64-bit" in name or "64bit" in name):
                        if name.endswith((".zip", ".tar.gz", ".tgz")):
                            download_url = asset.get("browser_download_url")
                            archive_name = asset.get("name")
                            break

            if not download_url:
                return False, f"No pre-compiled binary found for {os_match}/{arch_match} on GitHub"

            # Download and extract archive
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_archive = Path(tmp_dir) / archive_name
                dl_req = urllib.request.Request(download_url, headers=headers)
                with urllib.request.urlopen(dl_req, timeout=60) as dl_resp, open(tmp_archive, "wb") as out_f:
                    shutil.copyfileobj(dl_resp, out_f)

                # Extract
                extract_dir = Path(tmp_dir) / "extracted"
                extract_dir.mkdir(exist_ok=True)

                if archive_name.endswith(".zip"):
                    with zipfile.ZipFile(tmp_archive, "r") as zf:
                        zf.extractall(extract_dir)
                elif archive_name.endswith((".tar.gz", ".tgz")):
                    with tarfile.open(tmp_archive, "r:*") as tf:
                        tf.extractall(extract_dir)

                # Locate the binary inside extracted files
                bin_ext = ".exe" if sys.platform == "win32" else ""
                target_stem = bin_name.lower()
                found_bin = None

                for candidate in extract_dir.rglob("*"):
                    if candidate.is_file():
                        c_stem = candidate.stem.lower()
                        if c_stem == target_stem:
                            found_bin = candidate
                            break

                if not found_bin:
                    # Look for executable files
                    for candidate in extract_dir.rglob("*"):
                        if candidate.is_file() and not candidate.name.endswith((".md", ".txt", ".yaml", ".json")):
                            found_bin = candidate
                            break

                if found_bin:
                    shutil.copy2(found_bin, expected_bin)
                    if sys.platform != "win32":
                        os.chmod(expected_bin, 0o755)
                    return True, f"Downloaded GitHub release ({archive_name})"
                else:
                    return False, f"Archive {archive_name} did not contain {bin_name}"

        except Exception as e:
            return False, f"GitHub download error: {e}"

    @classmethod
    def install_all_missing(cls, missing_tools: list[str], console: Optional[Console] = None) -> dict[str, bool]:
        """Installs all missing tools sequentially and reports progress."""
        results = {}
        c = console or Console()
        target_dir = cls.get_target_dir()

        c.print(f"[bold cyan]Managed Bin Directory:[/bold cyan] {target_dir}\n")

        for tool in missing_tools:
            c.print(f"[dim]•[/dim] Installing [bold]{tool}[/bold]...", end=" ")
            success, msg = cls.install_tool(tool)
            results[tool] = success
            if success:
                c.print(f"[green]✔ Succeeded[/green] ({msg})")
            else:
                c.print(f"[red]✖ Failed[/red] ({msg})")

        return results
