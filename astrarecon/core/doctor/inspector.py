"""System Environment and Tool Dependency Inspector."""

import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ToolStatus:
    """Diagnostic status for a specific security binary."""
    name: str
    installed: bool
    path: Optional[str] = None
    version: Optional[str] = None
    error: Optional[str] = None


@dataclass
class SystemEnvironment:
    """Host machine runtime diagnostics."""
    os_name: str
    os_version: str
    kernel: str
    arch: str
    python_version: str
    go_installed: bool
    go_version: Optional[str] = None
    path_entries: list[str] = field(default_factory=list)
    managed_bin_in_path: bool = False
    tools: dict[str, ToolStatus] = field(default_factory=dict)


class EnvironmentInspector:
    """Inspects the local operating environment and checks tool availability."""

    CORE_TOOLS = {
        "subfinder": {"args": ["-version"], "regex": r"v?([0-9]+\.[0-9]+(\.[0-9]+)?)"},
        "assetfinder": {"args": ["-h"], "regex": r"(assetfinder)"},
        "amass": {"args": ["version"], "regex": r"v?([0-9]+\.[0-9]+(\.[0-9]+)?)"},
        "dnsx": {"args": ["-version"], "regex": r"v?([0-9]+\.[0-9]+(\.[0-9]+)?)"},
        "httpx": {"args": ["-version"], "regex": r"v?([0-9]+\.[0-9]+(\.[0-9]+)?)"},
        "naabu": {"args": ["-version"], "regex": r"v?([0-9]+\.[0-9]+(\.[0-9]+)?)"},
        "katana": {"args": ["-version"], "regex": r"v?([0-9]+\.[0-9]+(\.[0-9]+)?)"},
        "nuclei": {"args": ["-version"], "regex": r"v?([0-9]+\.[0-9]+(\.[0-9]+)?)"},
        "dalfox": {"args": ["--version"], "regex": r"v?([0-9]+\.[0-9]+(\.[0-9]+)?)"},
        "gau": {"args": ["--version"], "regex": r"v?([0-9]+\.[0-9]+(\.[0-9]+)?)"},
        "waybackurls": {"args": ["-h"], "regex": r"(waybackurls)"},
        "linkfinder": {"args": ["-h"], "regex": r"(linkfinder)"},
        "subenum": {"args": ["-v"], "regex": r"([0-9]{4}-[0-9]{2}-[0-9]{2})"},
    }

    @classmethod
    def get_managed_bin_dir(cls) -> Path:
        """Returns the ~/.astrarecon/bin path where managed binaries are stored."""
        return Path.home() / ".astrarecon" / "bin"

    @classmethod
    def inspect(cls) -> SystemEnvironment:
        """Performs a comprehensive diagnostic scan of the host."""
        managed_bin = cls.get_managed_bin_dir()
        path_var = os.environ.get("PATH", "")
        path_entries = [p for p in path_var.split(os.pathsep) if p]
        managed_in_path = str(managed_bin) in path_entries

        # OS information
        os_name = platform.system()
        os_version = platform.release()
        arch = platform.machine()
        kernel = platform.version()

        if os_name == "Linux":
            try:
                import distro  # type: ignore
                os_name = distro.name(pretty=True)
            except ImportError:
                try:
                    with open("/etc/os-release") as f:
                        for line in f:
                            if line.startswith("PRETTY_NAME="):
                                os_name = line.split("=", 1)[1].strip().strip('"')
                                break
                except Exception:
                    pass

        python_ver = platform.python_version()

        # Check Go compiler
        go_path = shutil.which("go")
        go_installed = go_path is not None
        go_version = None
        if go_installed:
            try:
                res = subprocess.run([go_path, "version"], capture_output=True, text=True, timeout=5)
                m = re.search(r"go(\d+\.\d+(\.\d+)?)", res.stdout)
                if m:
                    go_version = m.group(0)
            except Exception:
                pass

        env = SystemEnvironment(
            os_name=os_name,
            os_version=os_version,
            kernel=kernel,
            arch=arch,
            python_version=python_ver,
            go_installed=go_installed,
            go_version=go_version,
            path_entries=path_entries,
            managed_bin_in_path=managed_in_path,
        )

        # Check core tools
        for tool_name, spec in cls.CORE_TOOLS.items():
            env.tools[tool_name] = cls._check_tool(tool_name, spec["args"], spec["regex"], managed_bin)

        return env

    @classmethod
    def _check_tool(cls, name: str, args: list[str], regex: str, managed_bin: Path) -> ToolStatus:
        """Checks for the presence and version of a specific tool binary."""
        # Check ~/.astrarecon/bin first (managed security binaries), then standard PATH
        binary_path = None
        if (managed_bin / name).is_file():
            binary_path = str(managed_bin / name)
        elif (managed_bin / f"{name}.exe").is_file():
            binary_path = str(managed_bin / f"{name}.exe")
        elif (managed_bin / f"{name}.bat").is_file():
            binary_path = str(managed_bin / f"{name}.bat")
        else:
            binary_path = shutil.which(name)

        # Check user bin directories (~/go/bin, ~/.local/bin, $GOPATH/bin)
        if not binary_path:
            user_dirs = [
                Path.home() / "go" / "bin",
                Path.home() / ".local" / "bin",
            ]
            gopath = os.environ.get("GOPATH")
            if gopath:
                user_dirs.insert(0, Path(gopath) / "bin")
            for udir in user_dirs:
                for candidate in [udir / name, udir / f"{name}.exe", udir / f"{name}.bat"]:
                    if candidate.is_file():
                        binary_path = str(candidate.resolve())
                        break
                if binary_path:
                    break

        if not binary_path:
            return ToolStatus(name=name, installed=False)

        # Detect version
        version = None
        error = None
        try:
            res = subprocess.run([binary_path] + args, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=5)
            output = (res.stdout + " " + res.stderr).strip()

            # Disqualify conflicting Python httpx CLI package
            if name == "httpx" and ("no such option" in output.lower() or "next generation http client" in output.lower()):
                return ToolStatus(
                    name=name,
                    installed=False,
                    path=binary_path,
                    error="Conflicting Python 'httpx' client detected instead of ProjectDiscovery httpx",
                )

            match = re.search(regex, output, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else match.group(0)
            else:
                version = "installed"
        except subprocess.TimeoutExpired:
            error = "Version check timed out"
        except Exception as e:
            error = str(e)

        return ToolStatus(
            name=name,
            installed=True,
            path=binary_path,
            version=version,
            error=error,
        )
