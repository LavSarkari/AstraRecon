"""Plugin Management CLI Commands: List, Add, Remove, and Inspect security tool plugins."""

import re
import shlex
import shutil
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

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
from astrarecon.core.doctor.inspector import EnvironmentInspector
from astrarecon.core.models.plugin import (
    CachePolicyConfig,
    InputPort,
    OutputPort,
    PluginBinary,
    PluginExecution,
    PluginManifest,
)
from astrarecon.core.models.types import DataType
from astrarecon.core.plugins.loader import PluginLoader

app = typer.Typer(help="Manage, register, and inspect security tool plugins.")
console = Console(legacy_windows=False)

# Smart conventions for standard reconnaissance stages
STAGE_DEFAULTS = {
    "subdomains": {
        "input_name": "target",
        "input_type": DataType.TARGET_DOMAIN,
        "input_source": "param",
        "output_name": "subdomains",
        "output_type": DataType.FQDN,
        "output_file": "subdomains.txt",
        "output_format": "text_lines",
        "desc": "Subdomain discovery tool",
    },
    "dns": {
        "input_name": "hosts",
        "input_type": DataType.FQDN,
        "input_source": "artifact",
        "output_name": "valid_hosts",
        "output_type": DataType.FQDN,
        "output_file": "valid_hosts.txt",
        "output_format": "text_lines",
        "desc": "DNS resolution and validation tool",
    },
    "ports": {
        "input_name": "hosts",
        "input_type": DataType.FQDN,
        "input_source": "artifact",
        "output_name": "ports",
        "output_type": DataType.PORT_SERVICE,
        "output_file": "open_ports.txt",
        "output_format": "text_lines",
        "desc": "Port scanning and service detection tool",
    },
    "live_hosts": {
        "input_name": "targets",
        "input_type": DataType.FQDN,
        "input_source": "artifact",
        "output_name": "endpoints",
        "output_type": DataType.HTTP_URL,
        "output_file": "live_hosts.txt",
        "output_format": "text_lines",
        "desc": "HTTP server live host prober",
    },
    "crawling": {
        "input_name": "endpoints",
        "input_type": DataType.HTTP_URL,
        "input_source": "artifact",
        "output_name": "urls",
        "output_type": DataType.HTTP_URL,
        "output_file": "crawled_urls.txt",
        "output_format": "text_lines",
        "desc": "Web endpoint crawler / archive harvester",
    },
    "urls": {
        "input_name": "endpoints",
        "input_type": DataType.HTTP_URL,
        "input_source": "artifact",
        "output_name": "urls",
        "output_type": DataType.HTTP_URL,
        "output_file": "urls.txt",
        "output_format": "text_lines",
        "desc": "URL discovery and extraction tool",
    },
    "vulns": {
        "input_name": "targets",
        "input_type": DataType.HTTP_URL,
        "input_source": "artifact",
        "output_name": "findings",
        "output_type": DataType.FINDING,
        "output_file": "findings.jsonl",
        "output_format": "jsonl",
        "desc": "Automated vulnerability scanner",
    },
}

DEFAULT_FALLBACK = {
    "input_name": "input",
    "input_type": DataType.RAW_TEXT,
    "input_source": "artifact",
    "output_name": "output",
    "output_type": DataType.RAW_TEXT,
    "output_file": "output.txt",
    "output_format": "text_lines",
    "desc": "Custom reconnaissance plugin",
}


@app.command("list")
def list_plugins():
    """List all installed security tool plugins."""
    table = Table(
        title="Registered Tool Plugins",
        show_header=True,
        header_style=f"bold {COLOR_ACCENT}",
        box=ROUNDED,
        border_style=COLOR_DIVIDER,
    )
    table.add_column("Plugin ID", style=f"bold {COLOR_PRIMARY}", width=14)
    table.add_column("Stage", style=f"{COLOR_SECONDARY}", width=12)
    table.add_column("Binary", style=f"bold {COLOR_PRIMARY}", width=13)
    table.add_column("Tool Version", style=f"{COLOR_ACCENT}", width=15)
    table.add_column("Plugin Rev", style="dim", width=12)
    table.add_column("Status", width=14)

    registry = PluginLoader.load_all_plugins()
    env = EnvironmentInspector.inspect()
    managed_bin = EnvironmentInspector.get_managed_bin_dir()

    manifests = sorted(registry.list_all(), key=lambda m: m.id)

    for m in manifests:
        bin_name = m.binary.name
        tool_status = env.tools.get(bin_name)
        is_installed = False
        detected_version = "[dim]--[/dim]"

        if tool_status and tool_status.installed:
            is_installed = True
            raw_ver = tool_status.version or "detected"
            detected_version = f"v{raw_ver}" if raw_ver[0].isdigit() else raw_ver
        elif shutil.which(bin_name):
            is_installed = True
            detected_version = "detected"
        elif (managed_bin / bin_name).is_file() or (managed_bin / f"{bin_name}.exe").is_file() or (managed_bin / f"{bin_name}.bat").is_file():
            is_installed = True
            detected_version = "detected"

        status_text = f"[{COLOR_SUCCESS}]✓ Installed[/{COLOR_SUCCESS}]" if is_installed else f"[{COLOR_WARNING}]✗ Missing[/{COLOR_WARNING}]"
        table.add_row(m.id, m.stage, bin_name, detected_version, f"v{m.plugin_version}", status_text)

    console.print(table)


@app.command("add")
def add_plugin(
    name: str = typer.Argument(..., help="Unique identifier for the new tool (e.g. findomain, masscan, ffuf)"),
    cmd: str = typer.Option(
        ...,
        "--cmd",
        "-c",
        help="Command execution template (e.g. 'findomain -t {target} -u {output}')",
    ),
    stage: str = typer.Option(
        "subdomains",
        "--stage",
        "-s",
        help="Pipeline stage: subdomains | dns | ports | live_hosts | crawling | urls | vulns | custom",
    ),
    binary: Optional[str] = typer.Option(
        None,
        "--binary",
        "-b",
        help="Binary executable name (defaults to tool name)",
    ),
    description: Optional[str] = typer.Option(
        None,
        "--description",
        "--desc",
        "-d",
        help="Short description of what the tool does",
    ),
    author: Optional[str] = typer.Option(
        "Custom",
        "--author",
        "-a",
        help="Plugin author or maintainer name",
    ),
    input_name: Optional[str] = typer.Option(
        None,
        "--input-name",
        help="Input port identifier (e.g. target, hosts, endpoints)",
    ),
    input_type: Optional[str] = typer.Option(
        None,
        "--input-type",
        help="Input DataType: TargetDomain | FQDN | HTTPUrl | RawText",
    ),
    input_source: Optional[str] = typer.Option(
        None,
        "--input-source",
        help="Input source mode: 'param' (CLI argument string) or 'artifact' (file stream)",
    ),
    output_name: Optional[str] = typer.Option(
        None,
        "--output-name",
        help="Output port identifier (e.g. subdomains, valid_hosts, ports, urls, findings)",
    ),
    output_type: Optional[str] = typer.Option(
        None,
        "--output-type",
        help="Output DataType: FQDN | HTTPUrl | PortService | Finding | RawText",
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "--output-file",
        help="Output filename written by the tool (e.g. subdomains.txt, findings.jsonl)",
    ),
    output_format: Optional[str] = typer.Option(
        None,
        "--output-format",
        help="Output serialization format: text_lines | jsonl | json",
    ),
    timeout: int = typer.Option(
        600,
        "--timeout",
        help="Execution timeout in seconds (default: 600s)",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite plugin if it already exists",
    ),
):
    """Add and register a new custom security tool plugin without writing YAML."""
    clean_id = re.sub(r"[^a-zA-Z0-9_\-]", "", name.lower().strip())
    if not clean_id:
        console.print(f"[bold {COLOR_ERROR}]Error:[/bold {COLOR_ERROR}] Invalid plugin name '{name}'. Use alphanumeric characters, dashes, or underscores.")
        raise typer.Exit(code=1)

    bin_name = (binary or clean_id).strip()
    norm_stage = stage.lower().strip()
    stage_conf = STAGE_DEFAULTS.get(norm_stage, DEFAULT_FALLBACK)

    # Determine input and output port properties with smart defaults
    in_name = input_name or stage_conf["input_name"]
    in_type_str = input_type or stage_conf["input_type"]
    in_source = input_source or stage_conf["input_source"]

    out_name = output_name or stage_conf["output_name"]
    out_type_str = output_type or stage_conf["output_type"]
    out_filename = output_file or stage_conf["output_file"]
    out_fmt = output_format or stage_conf["output_format"]

    # Parse and normalize command execution arguments
    try:
        raw_tokens = shlex.split(cmd)
    except Exception as e:
        console.print(f"[bold {COLOR_ERROR}]Error parsing command template:[/bold {COLOR_ERROR}] {e}")
        raise typer.Exit(code=1)

    if not raw_tokens:
        console.print(f"[bold {COLOR_ERROR}]Error:[/bold {COLOR_ERROR}] Empty command provided.")
        raise typer.Exit(code=1)

    # If first token is the binary itself (or absolute path to it), strip it from args
    first_tok = raw_tokens[0]
    if first_tok == bin_name or first_tok.endswith("/" + bin_name) or first_tok.endswith("\\" + bin_name):
        arg_tokens = raw_tokens[1:]
    else:
        arg_tokens = raw_tokens

    # Replace intuitive shorthand variables with standard AstraRecon template expressions
    normalized_args = []
    for tok in arg_tokens:
        t = tok
        # Input shorthands
        t = re.sub(r"\{target\}", f"{{inputs.{in_name}}}", t, flags=re.IGNORECASE)
        t = re.sub(r"\{hosts\}", f"{{inputs.{in_name}}}", t, flags=re.IGNORECASE)
        t = re.sub(r"\{endpoints\}", f"{{inputs.{in_name}}}", t, flags=re.IGNORECASE)
        t = re.sub(r"\{targets\}", f"{{inputs.{in_name}}}", t, flags=re.IGNORECASE)
        t = re.sub(r"\{input\}", f"{{inputs.{in_name}}}", t, flags=re.IGNORECASE)

        # Output shorthands
        t = re.sub(r"\{output\}", f"{{outputs.{out_name}}}", t, flags=re.IGNORECASE)
        t = re.sub(r"\{outputs\}", f"{{outputs.{out_name}}}", t, flags=re.IGNORECASE)
        t = re.sub(r"\{subdomains\}", f"{{outputs.{out_name}}}", t, flags=re.IGNORECASE)
        t = re.sub(r"\{valid_hosts\}", f"{{outputs.{out_name}}}", t, flags=re.IGNORECASE)
        t = re.sub(r"\{ports\}", f"{{outputs.{out_name}}}", t, flags=re.IGNORECASE)
        t = re.sub(r"\{urls\}", f"{{outputs.{out_name}}}", t, flags=re.IGNORECASE)
        t = re.sub(r"\{findings\}", f"{{outputs.{out_name}}}", t, flags=re.IGNORECASE)
        normalized_args.append(t)

    # Build manifest data structure
    manifest_data = {
        "schema_version": 1,
        "id": clean_id,
        "name": clean_id.replace("_", " ").replace("-", " ").title(),
        "plugin_version": "1.0.0",
        "stage": norm_stage,
        "description": description or stage_conf["desc"],
        "author": author or "Custom",
        "binary": {
            "name": bin_name,
            "check_args": ["-version"],
            "version_regex": r"v?([0-9]+\.[0-9]+(\.[0-9]+)?)",
        },
        "inputs": [
            {
                "name": in_name,
                "type": in_type_str.value if hasattr(in_type_str, "value") else str(in_type_str),
                "required": True,
                "source": in_source,
            }
        ],
        "outputs": [
            {
                "name": out_name,
                "type": out_type_str.value if hasattr(out_type_str, "value") else str(out_type_str),
                "format": out_fmt,
                "filename": out_filename,
            }
        ],
        "execution": {
            "command": bin_name,
            "args": normalized_args,
            "timeout_seconds": timeout,
            "retry_count": 1,
        },
        "cache": {
            "policy": "fresh",
            "default_ttl_hours": 24,
        },
    }

    # Validate against PluginManifest Pydantic model
    try:
        manifest = PluginManifest.model_validate(manifest_data)
    except Exception as e:
        console.print(f"[bold {COLOR_ERROR}]Manifest Validation Error:[/bold {COLOR_ERROR}] {e}")
        raise typer.Exit(code=1)

    # Determine user plugin target directory
    user_plugin_dir = PluginLoader.get_user_plugin_dir() / clean_id
    manifest_path = user_plugin_dir / "plugin.yaml"

    if manifest_path.exists() and not force:
        console.print(f"\n[bold {COLOR_WARNING}]Warning:[/bold {COLOR_WARNING}] Plugin '{clean_id}' already exists at:")
        console.print(f"  [dim]{manifest_path}[/dim]")
        console.print(f"Use [bold]--force[/bold] / [bold]-f[/bold] to overwrite.\n")
        raise typer.Exit(code=1)

    user_plugin_dir.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(manifest_data, f, sort_keys=False, indent=2)

    # Check whether the binary is present on the system
    is_installed = bool(shutil.which(bin_name))
    managed_bin = EnvironmentInspector.get_managed_bin_dir()
    if (managed_bin / bin_name).is_file() or (Path.home() / "go" / "bin" / bin_name).is_file():
        is_installed = True

    status_badge = f"[{COLOR_SUCCESS}]Installed & Ready[/{COLOR_SUCCESS}]" if is_installed else f"[{COLOR_WARNING}]Not Found in PATH[/{COLOR_WARNING}] (Install '{bin_name}')"

    # Display rich confirmation panel
    info_lines = [
        f"Plugin ID:    [bold {COLOR_PRIMARY}]{clean_id}[/bold {COLOR_PRIMARY}]",
        f"Stage:        [bold {COLOR_ACCENT}]{norm_stage}[/bold {COLOR_ACCENT}]",
        f"Binary:       [bold white]{bin_name}[/bold white]  ({status_badge})",
        f"Manifest:     [dim]{manifest_path}[/dim]",
        f"Input Port:   {in_name} ([dim]{in_type_str}[/dim], source={in_source})",
        f"Output Port:  {out_name} ([dim]{out_type_str}[/dim], file={out_filename})",
        f"Command:      [dim]{bin_name} {' '.join(normalized_args)}[/dim]",
        "",
        f"[bold {COLOR_SUCCESS}]✔ Plugin successfully registered![/bold {COLOR_SUCCESS}]",
        "",
        f"[dim]To run this tool in your scans, use:[/dim]",
        f"  [bold {COLOR_ACCENT}]astrarecon scan example.com --with {clean_id}[/bold {COLOR_ACCENT}]",
    ]

    console.print()
    console.print(
        Panel(
            "\n".join(info_lines),
            title=f"[bold white]ASTRA[/bold white][bold {COLOR_PRIMARY}]RECON[/bold {COLOR_PRIMARY}] [dim]─ New Plugin Registered[/dim]",
            title_align="left",
            box=PANEL_BOX,
            border_style=COLOR_DIVIDER,
            padding=(1, 2),
        )
    )
    console.print()


@app.command("remove")
def remove_plugin(
    name: str = typer.Argument(..., help="ID of plugin to remove"),
    force: bool = typer.Option(False, "--force", "-f", help="Force removal without confirmation prompt"),
):
    """Remove a custom security tool plugin from AstraRecon."""
    clean_id = name.lower().strip()
    user_plugin_dir = PluginLoader.get_user_plugin_dir() / clean_id

    # Check if this is a built-in default plugin
    builtin_dir = PluginLoader.get_builtin_plugin_dir() / clean_id
    if builtin_dir.exists() and not user_plugin_dir.exists():
        console.print(f"\n[bold {COLOR_WARNING}]Notice:[/bold {COLOR_WARNING}] '{clean_id}' is a built-in system plugin.")
        console.print(f"[dim]Built-in plugins cannot be deleted from disk, but you can omit them during scans with:[/dim]")
        console.print(f"  [bold {COLOR_ACCENT}]astrarecon scan example.com --skip {clean_id}[/bold {COLOR_ACCENT}]\n")
        return

    if not user_plugin_dir.exists():
        console.print(f"\n[bold {COLOR_ERROR}]Error:[/bold {COLOR_ERROR}] Custom plugin '{clean_id}' not found in:")
        console.print(f"  [dim]{PluginLoader.get_user_plugin_dir()}[/dim]\n")
        raise typer.Exit(code=1)

    if not force:
        confirmed = typer.confirm(f"Are you sure you want to permanently remove custom plugin '{clean_id}'?")
        if not confirmed:
            console.print("[dim]Removal cancelled.[/dim]")
            return

    shutil.rmtree(user_plugin_dir, ignore_errors=True)
    console.print(f"\n[{COLOR_SUCCESS}]✔[/{COLOR_SUCCESS}] Custom plugin [bold {COLOR_PRIMARY}]{clean_id}[/bold {COLOR_PRIMARY}] successfully removed.\n")


@app.command("show")
def show_plugin(
    name: str = typer.Argument(..., help="ID of plugin to inspect"),
):
    """Inspect the declarative YAML manifest of an installed plugin."""
    clean_id = name.lower().strip()
    registry = PluginLoader.load_all_plugins()
    manifest = registry.get(clean_id)

    if not manifest:
        console.print(f"\n[bold {COLOR_ERROR}]Error:[/bold {COLOR_ERROR}] Plugin '{clean_id}' not found in registry.")
        console.print(f"[dim]Run 'astrarecon plugins list' to view all registered tools.[/dim]\n")
        raise typer.Exit(code=1)

    # Locate manifest file on disk
    user_file = PluginLoader.get_user_plugin_dir() / clean_id / "plugin.yaml"
    builtin_file = PluginLoader.get_builtin_plugin_dir() / clean_id / "plugin.yaml"
    manifest_path = user_file if user_file.exists() else builtin_file

    if manifest_path.exists():
        content = manifest_path.read_text(encoding="utf-8")
        syntax = Syntax(content, "yaml", theme="monokai", line_numbers=True)
        console.print()
        console.print(
            Panel(
                syntax,
                title=f"[bold white]ASTRA[/bold white][bold {COLOR_PRIMARY}]RECON[/bold {COLOR_PRIMARY}] [dim]─ Manifest: {manifest_path}[/dim]",
                title_align="left",
                box=PANEL_BOX,
                border_style=COLOR_DIVIDER,
                padding=(1, 2),
            )
        )
        console.print()
    else:
        # Fallback to model dump
        yaml_text = yaml.safe_dump(manifest.model_dump(), sort_keys=False, indent=2)
        console.print(Syntax(yaml_text, "yaml", theme="monokai"))
