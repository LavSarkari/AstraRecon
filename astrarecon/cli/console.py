"""Interactive Reconnaissance Console for AstraRecon."""

import os
import shlex
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.box import ROUNDED, SIMPLE
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
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
from astrarecon.core.doctor.inspector import EnvironmentInspector
from astrarecon.core.plugins.loader import PluginLoader
from astrarecon.core.sessions.manager import SessionManager

app = typer.Typer(help="Launch the interactive AstraRecon reconnaissance console.")
console = Console(legacy_windows=False)

ASCII_BANNER = r"""
       _   ____ _____ ____      _    ____  _____ ____ ___  _   _ 
      / \ / ___|_   _|  _ \    / \  |  _ \| ____/ ___/ _ \| \ | |
     / _ \\___ \ | | | |_) |  / _ \ | |_) |  _|| |  | | | |  \| |
    / ___ \___) || | |  _ <  / ___ \|  _ <| |__| |__| |_| | |\  |
   /_/   \_\____/ |_| |_| \_\/_/   \_\_| \_\_____\____\___/|_| \_|
"""


class ConsoleState:
    """Maintains state, active module context, and options inside the console."""

    def __init__(self):
        self.active_module: Optional[str] = "workflow/default"
        self.options = {
            "TARGET": "",
            "WORKFLOW": "default",
            "PROFILE": "auto",
            "PROXY": "",
            "WITH": "",
            "SKIP": "",
            "TOOLS": "",
            "DIFF_ONLY": "false",
            "FRESH": "false",
            "CLEAR": "false",
            "OUTPUT": "",
            "SCOPE_INCLUDE": "",
            "SCOPE_EXCLUDE": "",
        }

    def set_option(self, key: str, value: str) -> bool:
        norm_key = key.upper().strip()
        if norm_key in self.options:
            self.options[norm_key] = value.strip()
            # If changing WORKFLOW option, reflect in active_module if in workflow context
            if norm_key == "WORKFLOW" and self.active_module and self.active_module.startswith("workflow/"):
                self.active_module = f"workflow/{value.strip()}"
            return True
        return False

    def unset_option(self, key: str) -> bool:
        norm_key = key.upper().strip()
        if norm_key in self.options:
            if norm_key == "WORKFLOW":
                self.options["WORKFLOW"] = "default"
            elif norm_key == "PROFILE":
                self.options["PROFILE"] = "auto"
            elif norm_key in ("DIFF_ONLY", "FRESH", "CLEAR"):
                self.options[norm_key] = "false"
            else:
                self.options[norm_key] = ""
            return True
        return False


def render_banner(plugins=None, env=None, session_count=None):
    """Renders the startup banner with live environment telemetry."""
    if session_count is None:
        session_mgr = SessionManager()
        sessions_dir = session_mgr.base_dir
        session_count = len([d for d in sessions_dir.iterdir() if d.is_dir() and (d / "session.json").exists()]) if sessions_dir.exists() else 0
    if plugins is None:
        plugins = PluginLoader.load_all_plugins()
    if env is None:
        env = EnvironmentInspector.inspect()
    installed_count = sum(1 for status in env.tools.values() if status.installed)

    banner_text = Text(ASCII_BANNER.strip("\n"), style=f"bold {COLOR_PRIMARY}")

    stats_lines = [
        f"[bold white]AstraRecon Console[/bold white] v{__version__} [dim]─ Autonomous Reconnaissance Orchestrator[/dim]",
        "",
        f"  [bold {COLOR_SUCCESS}]+[/bold {COLOR_SUCCESS}] [bold white]{len(plugins.list_all())}[/bold white] Plugins registered  "
        f"([bold {COLOR_ACCENT}]{installed_count}[/bold {COLOR_ACCENT}] binaries detected in PATH)",
        f"  [bold {COLOR_SUCCESS}]+[/bold {COLOR_SUCCESS}] [bold white]4[/bold white] Workflow Presets (default, fast, passive, vuln)",
        f"  [bold {COLOR_SUCCESS}]+[/bold {COLOR_SUCCESS}] [bold white]{session_count}[/bold white] Saved Scan Sessions in ~/.astrarecon/sessions/",
        "",
        f"[dim]Type '[bold white]help[/bold white]' or '[bold white]?[/bold white]' to view available commands. Type '[bold white]show options[/bold white]' to inspect settings.[/dim]",
    ]

    console.print()
    console.print(banner_text)
    console.print()
    for line in stats_lines:
        console.print(line)
    console.print()


def show_options(state: ConsoleState):
    """Displays the options table for the active context."""
    table = Table(
        title=f"\n[bold white]Module Options[/bold white] ([bold {COLOR_PRIMARY}]{state.active_module or 'global'}[/bold {COLOR_PRIMARY}]):",
        title_justify="left",
        box=SIMPLE,
        header_style=f"bold {COLOR_PRIMARY}",
        padding=(0, 2),
    )
    table.add_column("Name", style=f"bold {COLOR_ACCENT}", width=16)
    table.add_column("Current Setting", style="bold white", width=22)
    table.add_column("Required", style="dim", width=10)
    table.add_column("Description", style=f"{COLOR_SECONDARY}")

    opts = [
        ("TARGET", state.options["TARGET"], "yes", "Target domain, URL, or CIDR (e.g. example.com)"),
        ("WORKFLOW", state.options["WORKFLOW"], "yes", "Preset: default | fast | passive | vuln"),
        ("PROFILE", state.options["PROFILE"], "no", "Execution profile: auto | safe | default | beast"),
        ("PROXY", state.options["PROXY"], "no", "Upstream HTTP/SOCKS5 proxy (e.g. http://127.0.0.1:8080)"),
        ("WITH", state.options["WITH"], "no", "Additional registered tool(s) to inject (e.g. findomain,dalfox)"),
        ("SKIP", state.options["SKIP"], "no", "Tool(s) to omit from scan (e.g. amass,gau)"),
        ("TOOLS", state.options["TOOLS"], "no", "Exact comma-separated list of tools to run"),
        ("DIFF_ONLY", state.options["DIFF_ONLY"], "no", "Scan only new attack surfaces since last baseline (true/false)"),
        ("FRESH", state.options["FRESH"], "no", "Force fresh scan without prompt (true/false)"),
        ("CLEAR", state.options["CLEAR"], "no", "Clear prior sessions for this target before scanning (true/false)"),
        ("OUTPUT", state.options["OUTPUT"], "no", "Save report to file (.json, .md, .csv)"),
        ("SCOPE_INCLUDE", state.options["SCOPE_INCLUDE"], "no", "Regex pattern of in-scope domains"),
        ("SCOPE_EXCLUDE", state.options["SCOPE_EXCLUDE"], "no", "Regex pattern of out-of-scope domains to quarantine"),
    ]

    for name, cur_val, req, desc in opts:
        val_str = cur_val if cur_val else "[dim]--[/dim]"
        req_str = f"[bold {COLOR_WARNING}]yes[/bold {COLOR_WARNING}]" if req == "yes" else "no"
        table.add_row(name, val_str, req_str, desc)

    console.print(table)
    console.print()


def show_workflows():
    """Lists available workflow presets."""
    table = Table(
        title="\n[bold white]Workflow Presets[/bold white]:",
        title_justify="left",
        box=ROUNDED,
        header_style=f"bold {COLOR_PRIMARY}",
        border_style=COLOR_DIVIDER,
    )
    table.add_column("Preset", style=f"bold {COLOR_ACCENT}", width=14)
    table.add_column("Stages / Tools", style="white", width=42)
    table.add_column("Description", style=f"{COLOR_SECONDARY}")

    table.add_row(
        "default",
        "subfinder, assetfinder, amass, dnsx, naabu, httpx, gau, katana, nuclei",
        "Full 12-stage reconnaissance & vulnerability assessment",
    )
    table.add_row(
        "fast",
        "subfinder, dnsx, httpx",
        "Lightweight discovery (quick attack surface map in seconds)",
    )
    table.add_row(
        "passive",
        "subfinder, assetfinder, gau",
        "Passive OSINT sources only (zero direct target network packets)",
    )
    table.add_row(
        "vuln",
        "subfinder, dnsx, httpx, nuclei",
        "Vulnerability scanning focused pipeline",
    )

    console.print(table)
    console.print()


def show_plugins():
    """Lists registered plugins with detection status."""
    from astrarecon.cli.plugins import list_plugins
    list_plugins()


def show_sessions():
    """Lists recorded scan sessions."""
    from astrarecon.cli.sessions import list_sessions
    list_sessions()


def render_help():
    """Displays comprehensive console commands help."""
    table = Table(
        title="\n[bold white]Console Commands[/bold white]:",
        title_justify="left",
        box=ROUNDED,
        header_style=f"bold {COLOR_PRIMARY}",
        border_style=COLOR_DIVIDER,
    )
    table.add_column("Command", style=f"bold {COLOR_ACCENT}", width=24)
    table.add_column("Description", style="white")

    commands = [
        ("use <module>", "Select active workflow or plugin context (e.g. use workflow/fast, use nuclei)"),
        ("back", "Move back to root prompt context"),
        ("show options", "Display current configuration parameters and values"),
        ("show workflows", "List available workflow presets"),
        ("show plugins", "List all registered tool plugins and binary statuses"),
        ("show sessions", "List recorded scan sessions"),
        ("set <OPTION> <VALUE>", "Set parameter value (e.g. set TARGET example.com, set PROXY http://127.0.0.1:8080)"),
        ("unset <OPTION>", "Reset parameter to default/empty value"),
        ("run / scan / exploit", "Execute active workflow with configured parameters"),
        ("sessions -i <session_id>", "Inspect detailed checkpoints and logs of a past session"),
        ("sessions clear", "Clear all saved sessions to reclaim disk space"),
        ("export ai <session_id>", "Generate LLM-optimized prompt distillation bundle"),
        ("doctor", "Inspect environment tools and Go binaries"),
        ("update", "Check for and install latest updates (e.g. update --source github)"),
        ("plugins add <name> ...", "Register a new custom tool without writing YAML"),
        ("plugins remove <name>", "Delete a custom tool plugin"),
        ("banner", "Display AstraRecon ASCII banner and telemetry"),
        ("clear", "Clear terminal screen"),
        ("exit / quit", "Exit AstraRecon interactive console"),
    ]

    for cmd, desc in commands:
        table.add_row(cmd, desc)

    console.print(table)
    console.print()


def execute_scan(state: ConsoleState, args: Optional[list[str]] = None):
    """Executes the scan engine using parameters stored in state or passed inline."""
    # Parse any inline arguments passed directly to scan/run (e.g. scan example.com --workflow fast)
    if args:
        i = 0
        while i < len(args):
            arg = args[i]
            if not arg.startswith("-") and (i == 0 or not state.options["TARGET"]):
                state.set_option("TARGET", arg)
                i += 1
            elif arg in ("--workflow", "-w") and i + 1 < len(args):
                state.set_option("WORKFLOW", args[i + 1])
                i += 2
            elif arg in ("--profile", "-p") and i + 1 < len(args):
                state.set_option("PROFILE", args[i + 1])
                i += 2
            elif arg == "--proxy" and i + 1 < len(args):
                state.set_option("PROXY", args[i + 1])
                i += 2
            elif arg == "--with" and i + 1 < len(args):
                cur = state.options["WITH"]
                state.set_option("WITH", f"{cur},{args[i+1]}" if cur else args[i+1])
                i += 2
            elif arg == "--skip" and i + 1 < len(args):
                cur = state.options["SKIP"]
                state.set_option("SKIP", f"{cur},{args[i+1]}" if cur else args[i+1])
                i += 2
            elif arg == "--tools" and i + 1 < len(args):
                state.set_option("TOOLS", args[i + 1])
                i += 2
            elif arg in ("--diff-only",):
                state.set_option("DIFF_ONLY", "true")
                i += 1
            elif arg in ("--fresh", "-f"):
                state.set_option("FRESH", "true")
                i += 1
            elif arg in ("--clear",):
                state.set_option("CLEAR", "true")
                i += 1
            elif arg in ("--output", "-o") and i + 1 < len(args):
                state.set_option("OUTPUT", args[i + 1])
                i += 2
            else:
                if not arg.startswith("-"):
                    state.set_option("TARGET", arg)
                i += 1

    target = state.options["TARGET"].strip()
    if not target:
        console.print(f"\n[bold {COLOR_ERROR}][-] Cannot run scan: TARGET option is not set.[/bold {COLOR_ERROR}]")
        console.print(f"[dim]Usage: [bold white]scan example.com[/bold white] OR [bold white]set TARGET example.com[/bold white] then run.[/dim]\n")
        return

    workflow = state.options["WORKFLOW"].strip() or "default"
    profile = state.options["PROFILE"].strip() or "auto"
    proxy = state.options["PROXY"].strip() or None
    diff_only = state.options["DIFF_ONLY"].strip().lower() in ("true", "1", "yes")
    fresh = state.options["FRESH"].strip().lower() in ("true", "1", "yes")
    clear = state.options["CLEAR"].strip().lower() in ("true", "1", "yes")
    scope_include = state.options["SCOPE_INCLUDE"].strip() or None
    scope_exclude = state.options["SCOPE_EXCLUDE"].strip() or None
    out_file = Path(state.options["OUTPUT"].strip()) if state.options["OUTPUT"].strip() else None

    # Parse with / skip / tools lists
    with_raw = state.options["WITH"].strip()
    with_list = [w.strip() for w in with_raw.replace(" ", ",").split(",") if w.strip()] if with_raw else None

    skip_raw = state.options["SKIP"].strip()
    skip_list = [s.strip() for s in skip_raw.replace(" ", ",").split(",") if s.strip()] if skip_raw else None

    tools_raw = state.options["TOOLS"].strip() or None

    console.print(f"\n[*] Launching reconnaissance against [bold white]{target}[/bold white] (workflow=[bold {COLOR_ACCENT}]{workflow}[/bold {COLOR_ACCENT}])...")

    from astrarecon.cli.scan import run_scan
    try:
        run_scan(
            target=target,
            workflow=workflow,
            profile=profile,
            diff_only=diff_only,
            resume=None,
            fresh=fresh,
            scope_include=scope_include,
            scope_exclude=scope_exclude,
            proxy=proxy,
            header=None,
            output=out_file,
            output_format=None,
            no_results=False,
            clear=clear,
            with_tools=with_list,
            skip_tools=skip_list,
            tools=tools_raw,
        )
    except typer.Exit:
        pass
    except KeyboardInterrupt:
        console.print(f"\n[bold {COLOR_WARNING}][!] Scan interrupted by user.[/bold {COLOR_WARNING}]\n")
    except Exception as e:
        console.print(f"\n[bold {COLOR_ERROR}][-] Execution error:[/bold {COLOR_ERROR}] {e}\n")


def build_completer():
    """Builds dynamic NestedCompleter for prompt_toolkit tab auto-completion."""
    try:
        from prompt_toolkit.completion import NestedCompleter

        plugins = PluginLoader.load_all_plugins()
        plugin_keys = {m.id: None for m in plugins.list_all()}

        workflows = {
            "workflow/default": None,
            "workflow/fast": None,
            "workflow/passive": None,
            "workflow/vuln": None,
            "default": None,
            "fast": None,
            "passive": None,
            "vuln": None,
        }
        workflows.update({f"plugin/{pid}": None for pid in plugin_keys})

        options_dict = {
            "TARGET": None,
            "WORKFLOW": {"default": None, "fast": None, "passive": None, "vuln": None},
            "PROFILE": {"auto": None, "safe": None, "default": None, "beast": None},
            "PROXY": None,
            "WITH": plugin_keys,
            "SKIP": plugin_keys,
            "TOOLS": None,
            "DIFF_ONLY": {"true": None, "false": None},
            "FRESH": {"true": None, "false": None},
            "CLEAR": {"true": None, "false": None},
            "OUTPUT": None,
            "SCOPE_INCLUDE": None,
            "SCOPE_EXCLUDE": None,
        }

        return NestedCompleter.from_nested_dict({
            "use": workflows,
            "back": None,
            "set": options_dict,
            "unset": {k: None for k in options_dict.keys()},
            "show": {
                "options": None,
                "workflows": None,
                "presets": None,
                "plugins": None,
                "sessions": None,
                "info": None,
            },
            "run": None,
            "scan": None,
            "exploit": None,
            "sessions": {
                "-l": None,
                "-i": None,
                "clear": None,
                "prune": None,
            },
            "export": {
                "ai": None,
            },
            "doctor": {
                "--install-missing": None,
            },
            "update": {
                "--source": {"github": None, "pypi": None},
                "--check": None,
                "--force": None,
                "github": None,
                "pypi": None,
            },
            "plugins": {
                "list": None,
                "add": None,
                "remove": None,
                "show": None,
            },
            "banner": None,
            "clear": None,
            "help": None,
            "?": None,
            "exit": None,
            "quit": None,
        })
    except Exception:
        return None


@app.callback(invoke_without_command=True)
def run_console():
    """Launch the interactive reconnaissance console."""
    from astrarecon.cli.ui.loader import AstraLoader

    state = ConsoleState()
    plugins = None
    env = None
    session_count = 0
    has_pt = False
    session = None

    with AstraLoader("Aligning constellation telemetry & plugins...") as loader:
        plugins = PluginLoader.load_all_plugins()
        loader.update("Inspecting orbital tool binaries...")
        env = EnvironmentInspector.inspect()

        session_mgr = SessionManager()
        sessions_dir = session_mgr.base_dir
        session_count = (
            len([d for d in sessions_dir.iterdir() if d.is_dir() and (d / "session.json").exists()])
            if sessions_dir.exists()
            else 0
        )

        loader.update("Building command completions & history...")
        try:
            from prompt_toolkit import PromptSession
            from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
            from prompt_toolkit.formatted_text import HTML
            from prompt_toolkit.history import FileHistory

            history_file = Path.home() / ".astrarecon" / "console_history"
            history_file.parent.mkdir(parents=True, exist_ok=True)
            session = PromptSession(
                history=FileHistory(str(history_file)),
                auto_suggest=AutoSuggestFromHistory(),
                completer=build_completer(),
            )
            has_pt = True
        except Exception:
            has_pt = False

    render_banner(plugins=plugins, env=env, session_count=session_count)

    while True:
        try:
            # Build prompt: astrarecon (workflow/default) >
            if state.active_module:
                prompt_label = f"astrarecon ({state.active_module}) > "
                pt_prompt = HTML(f"<ansicyan><b>astrarecon</b></ansicyan> (<ansired><b>{state.active_module}</b></ansired>) &gt; ")
            else:
                prompt_label = "astrarecon > "
                pt_prompt = HTML("<ansicyan><b>astrarecon</b></ansicyan> &gt; ")

            if has_pt:
                line = session.prompt(pt_prompt)
            else:
                line = input(prompt_label)

            line = line.strip()
            if not line:
                continue

            # Split command line into tokens
            try:
                tokens = shlex.split(line)
            except Exception:
                tokens = line.split()

            if not tokens:
                continue

            cmd = tokens[0].lower()
            args = tokens[1:]

            # -------------------------------------------------------------
            # Command Router
            # -------------------------------------------------------------
            if cmd in ("exit", "quit", "q"):
                console.print("[dim]Exiting AstraRecon console. Goodbye![/dim]\n")
                break

            elif cmd in ("help", "?"):
                render_help()

            elif cmd == "banner":
                render_banner()

            elif cmd == "clear":
                os.system("clear" if os.name != "nt" else "cls")

            elif cmd == "back":
                state.active_module = None
                console.print("[dim]Returned to root context.[/dim]")

            elif cmd == "use":
                if not args:
                    console.print(f"[bold {COLOR_WARNING}]Usage:[/bold {COLOR_WARNING}] use <workflow/preset | plugin/name>")
                    console.print("[dim]Examples: use workflow/fast, use default, use plugin/nuclei[/dim]")
                else:
                    mod = args[0].strip().lower()
                    if mod in ("default", "fast", "passive", "vuln"):
                        state.active_module = f"workflow/{mod}"
                        state.set_option("WORKFLOW", mod)
                    elif mod.startswith("workflow/"):
                        sub = mod.split("/", 1)[1]
                        state.active_module = mod
                        state.set_option("WORKFLOW", sub)
                    elif mod.startswith("plugin/"):
                        state.active_module = mod
                    else:
                        state.active_module = f"workflow/{mod}"
                        state.set_option("WORKFLOW", mod)

            elif cmd == "show":
                sub = args[0].lower() if args else "options"
                if sub in ("options", "opt"):
                    show_options(state)
                elif sub in ("workflows", "presets"):
                    show_workflows()
                elif sub in ("plugins", "tools"):
                    show_plugins()
                elif sub in ("sessions", "history"):
                    show_sessions()
                elif sub == "info":
                    show_options(state)
                else:
                    console.print(f"[bold {COLOR_ERROR}]Unknown show category:[/bold {COLOR_ERROR}] '{sub}'")
                    console.print("[dim]Valid: show options, show workflows, show plugins, show sessions[/dim]")

            elif cmd == "set":
                if len(args) < 2:
                    console.print(f"[bold {COLOR_WARNING}]Usage:[/bold {COLOR_WARNING}] set <OPTION> <VALUE>")
                    console.print("[dim]Example: set TARGET example.com[/dim]")
                else:
                    k, v = args[0], " ".join(args[1:])
                    ok = state.set_option(k, v)
                    if ok:
                        console.print(f"{k.upper()} => [bold white]{v}[/bold white]")
                    else:
                        console.print(f"[bold {COLOR_ERROR}]Unknown option:[/bold {COLOR_ERROR}] '{k}'")
                        console.print("[dim]Type 'show options' to view all available parameters.[/dim]")

            elif cmd == "unset":
                if not args:
                    console.print(f"[bold {COLOR_WARNING}]Usage:[/bold {COLOR_WARNING}] unset <OPTION>")
                else:
                    k = args[0]
                    ok = state.unset_option(k)
                    if ok:
                        console.print(f"Unset {k.upper()}")
                    else:
                        console.print(f"[bold {COLOR_ERROR}]Unknown option:[/bold {COLOR_ERROR}] '{k}'")

            elif cmd in ("run", "scan", "exploit"):
                execute_scan(state, args)

            elif cmd in ("options", "opt"):
                show_options(state)

            elif cmd in ("workflows", "presets", "wf"):
                show_workflows()

            elif cmd in ("sessions", "session", "ses", "sess"):
                if not args or args[0] == "-l":
                    show_sessions()
                elif args[0] == "-i" and len(args) > 1:
                    from astrarecon.cli.sessions import inspect_session
                    inspect_session(args[1])
                elif args[0] == "clear":
                    from astrarecon.cli.sessions import clear_sessions
                    force_flag = "--force" in args or "-f" in args
                    clear_sessions(target=None, force=force_flag)
                elif len(args) == 1 and not args[0].startswith("-"):
                    # Quick inspect by session ID: sessions <session_id>
                    from astrarecon.cli.sessions import inspect_session
                    inspect_session(args[0])
                else:
                    show_sessions()

            elif cmd == "export":
                if len(args) >= 2 and args[0] == "ai":
                    from astrarecon.cli.export import export_ai_bundle
                    export_ai_bundle(args[1], None)
                else:
                    console.print("[dim]Usage: export ai <session_id>[/dim]")

            elif cmd in ("doctor", "doc"):
                from astrarecon.cli.doctor import run_doctor
                install_missing = "--install-missing" in args or "-i" in args
                run_doctor(install_missing=install_missing)

            elif cmd in ("update", "up"):
                from astrarecon.cli.update import run_update
                src = "github"
                if "pypi" in args:
                    src = "pypi"
                elif "--source" in args:
                    idx = args.index("--source")
                    if idx + 1 < len(args):
                        src = args[idx + 1]
                elif "-s" in args:
                    idx = args.index("-s")
                    if idx + 1 < len(args):
                        src = args[idx + 1]

                check_only = "--check" in args or "-c" in args
                force_flag = "--force" in args or "-f" in args
                try:
                    run_update(source=src, check=check_only, force=force_flag)
                except typer.Exit:
                    pass
                except Exception as e:
                    console.print(f"[bold {COLOR_ERROR}]Update error:[/bold {COLOR_ERROR}] {e}")

            elif cmd in ("plugins", "tools", "pl"):
                sub = args[0].lower() if args else "list"
                if sub == "list":
                    show_plugins()
                elif sub == "show" and len(args) > 1:
                    from astrarecon.cli.plugins import show_plugin
                    show_plugin(args[1])
                elif sub == "remove" and len(args) > 1:
                    from astrarecon.cli.plugins import remove_plugin
                    remove_plugin(args[1], force="--force" in args or "-f" in args)
                else:
                    show_plugins()

            else:
                console.print(f"[bold {COLOR_ERROR}]Unknown command:[/bold {COLOR_ERROR}] '{cmd}'")
                console.print("[dim]Type '[bold white]help[/bold white]' or '[bold white]?[/bold white]' to view available commands.[/dim]")

        except KeyboardInterrupt:
            # Ctrl+C inside REPL clears line
            console.print("\n[dim](^C - To exit AstraRecon console, type 'exit')[/dim]")
            continue
        except EOFError:
            # Ctrl+D cleanly exits
            console.print("\n[dim]Exiting console...[/dim]")
            break
        except Exception as e:
            console.print(f"\n[bold {COLOR_ERROR}]Console error:[/bold {COLOR_ERROR}] {e}\n")
