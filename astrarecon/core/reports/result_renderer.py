"""Result Renderer: Pretty-prints real scan output using Rich tables.

Reads from actual checkpoint artifact files written by the DAG engine
and renders structured, coloured Rich renderables for the terminal.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

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

console = Console(legacy_windows=False)


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class ScanResults:
    """Structured scan results extracted from session checkpoint artifacts."""

    target: str
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[dict] = field(default_factory=list)   # httpx jsonl rows
    findings: list[dict] = field(default_factory=list)     # nuclei jsonl rows

    @property
    def subdomain_count(self) -> int:
        return len(self.subdomains)

    @property
    def live_host_count(self) -> int:
        return len(self.live_hosts)

    @property
    def finding_count(self) -> int:
        return len(self.findings)


# ---------------------------------------------------------------------------
# Loader: reads real checkpoint artifact files
# ---------------------------------------------------------------------------

class ScanResultLoader:
    """Reads artifact files written by the DAG execution engine."""

    @staticmethod
    def load(session_dir: Path, target: str) -> ScanResults:
        results = ScanResults(target=target)
        artifacts_dir = session_dir / "artifacts"
        if not artifacts_dir.exists():
            return results

        # --- Subdomains: plain text files from subfinder / assetfinder / union_dedupe ---
        for txt_file in artifacts_dir.glob("*.txt"):
            lines = ScanResultLoader._read_lines(txt_file)
            if lines and not results.subdomains:
                results.subdomains = lines
            elif lines and len(lines) > len(results.subdomains):
                # Prefer the largest deduplicated set (union_dedupe output)
                results.subdomains = lines

        # --- Live hosts: httpx JSONL output ---
        for jl_file in sorted(artifacts_dir.glob("*.jsonl")):
            name = jl_file.stem.lower()
            if "finding" in name or "vuln" in name or "nuclei" in name:
                continue
            rows = ScanResultLoader._read_jsonl(jl_file)
            if rows and any(r.get("url") or r.get("host") for r in rows):
                if len(rows) > len(results.live_hosts):
                    results.live_hosts = rows

        # --- Findings: nuclei JSONL output ---
        for jl_file in artifacts_dir.glob("*.jsonl"):
            name = jl_file.stem.lower()
            if "finding" in name or "vuln" in name or "nuclei" in name:
                rows = ScanResultLoader._read_jsonl(jl_file)
                results.findings.extend(rows)

        return results

    @staticmethod
    def _read_lines(path: Path) -> list[str]:
        try:
            return [l.strip() for l in path.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
        except Exception:
            return []

    @staticmethod
    def _read_jsonl(path: Path) -> list[dict]:
        rows: list[dict] = []
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass
        return rows


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

class ScanResultsRenderer:
    """Renders ScanResults as Rich panels to the terminal."""

    # How many rows to show per table in the terminal (full data still saved to --output)
    _SUBDOMAIN_LIMIT = 50
    _HOST_LIMIT = 30
    _FINDING_LIMIT = 50

    @classmethod
    def render_all(cls, results: ScanResults, limit: bool = True) -> None:
        """Print all result sections to stdout."""
        console.print()
        console.print(Rule(
            title=f"[bold #1DA1FF]  SCAN RESULTS — {results.target}  [/bold #1DA1FF]",
            style=COLOR_DIVIDER,
        ))
        console.print()

        cls._render_subdomains(results, limit)
        cls._render_live_hosts(results, limit)
        cls._render_findings(results, limit)

        console.print()
        console.print(Rule(style=COLOR_DIVIDER))
        console.print()

    # ------------------------------------------------------------------
    # Subdomains
    # ------------------------------------------------------------------
    @classmethod
    def _render_subdomains(cls, results: ScanResults, limit: bool) -> None:
        subs = results.subdomains
        if not subs:
            console.print(f"[dim]  No subdomains discovered.[/dim]\n")
            return

        shown = subs[:cls._SUBDOMAIN_LIMIT] if limit else subs
        trimmed = len(subs) - len(shown)

        tbl = Table(
            show_header=True,
            header_style=f"bold {COLOR_ACCENT}",
            box=box.SIMPLE_HEAVY,
            border_style=COLOR_DIVIDER,
            padding=(0, 1),
            expand=False,
        )
        tbl.add_column("#", style=f"dim {COLOR_SECONDARY}", width=5, justify="right")
        tbl.add_column("Subdomain", style=f"bold {COLOR_PRIMARY}", min_width=38)

        for i, sub in enumerate(shown, 1):
            tbl.add_row(str(i), sub)

        panel = Panel(
            tbl,
            title=f"[bold {COLOR_SUCCESS}]✔ Subdomains Discovered[/bold {COLOR_SUCCESS}]  "
                  f"[dim]{len(subs)} total[/dim]",
            title_align="left",
            box=PANEL_BOX,
            border_style=COLOR_DIVIDER,
            padding=(0, 1),
        )
        console.print(panel)

        if trimmed > 0:
            console.print(f"  [dim]… and {trimmed} more — use [bold]--output results.json[/bold] to see all.[/dim]\n")
        else:
            console.print()

    # ------------------------------------------------------------------
    # Live Hosts
    # ------------------------------------------------------------------
    @classmethod
    def _render_live_hosts(cls, results: ScanResults, limit: bool) -> None:
        hosts = results.live_hosts
        if not hosts:
            console.print(f"[dim]  No live HTTP hosts probed yet.[/dim]\n")
            return

        shown = hosts[:cls._HOST_LIMIT] if limit else hosts
        trimmed = len(hosts) - len(shown)

        tbl = Table(
            show_header=True,
            header_style=f"bold {COLOR_ACCENT}",
            box=box.SIMPLE_HEAVY,
            border_style=COLOR_DIVIDER,
            padding=(0, 1),
            expand=True,
        )
        tbl.add_column("URL", style=f"bold {COLOR_PRIMARY}", min_width=40, no_wrap=True)
        tbl.add_column("Status", width=8, justify="center")
        tbl.add_column("Title", style=f"{COLOR_SECONDARY}", min_width=28)
        tbl.add_column("Technologies", style=f"dim {COLOR_SECONDARY}", min_width=20)

        for row in shown:
            url = row.get("url") or row.get("host") or ""
            status = str(row.get("status_code", ""))
            title = (row.get("title") or "").strip()[:60]
            tech = row.get("tech") or row.get("technologies") or []
            if isinstance(tech, list):
                tech_str = ", ".join(str(t) for t in tech[:4])
            else:
                tech_str = str(tech)

            # Status code coloring
            if status.startswith("2"):
                s_text = Text(status, style=f"bold {COLOR_SUCCESS}")
            elif status.startswith("3"):
                s_text = Text(status, style=f"bold {COLOR_ACCENT}")
            elif status.startswith("4"):
                s_text = Text(status, style=f"bold {COLOR_WARNING}")
            elif status.startswith("5"):
                s_text = Text(status, style=f"bold {COLOR_ERROR}")
            else:
                s_text = Text(status, style=f"dim {COLOR_SECONDARY}")

            tbl.add_row(url, s_text, title or "[dim]—[/dim]", tech_str or "[dim]—[/dim]")

        panel = Panel(
            tbl,
            title=f"[bold {COLOR_SUCCESS}]✔ Live HTTP Hosts[/bold {COLOR_SUCCESS}]  "
                  f"[dim]{len(hosts)} total[/dim]",
            title_align="left",
            box=PANEL_BOX,
            border_style=COLOR_DIVIDER,
            padding=(0, 1),
        )
        console.print(panel)

        if trimmed > 0:
            console.print(f"  [dim]… and {trimmed} more — use [bold]--output results.json[/bold] to see all.[/dim]\n")
        else:
            console.print()

    # ------------------------------------------------------------------
    # Findings / Vulnerabilities
    # ------------------------------------------------------------------
    @classmethod
    def _render_findings(cls, results: ScanResults, limit: bool) -> None:
        findings = results.findings
        if not findings:
            console.print(f"  [dim {COLOR_SUCCESS}]✔ No vulnerabilities detected.[/dim]\n")
            return

        shown = findings[:cls._FINDING_LIMIT] if limit else findings
        trimmed = len(findings) - len(shown)

        tbl = Table(
            show_header=True,
            header_style=f"bold {COLOR_ACCENT}",
            box=box.SIMPLE_HEAVY,
            border_style=COLOR_DIVIDER,
            padding=(0, 1),
            expand=True,
        )
        tbl.add_column("Severity", width=10, justify="center")
        tbl.add_column("Finding", style=f"bold {COLOR_PRIMARY}", min_width=36)
        tbl.add_column("Host", style=f"{COLOR_SECONDARY}", min_width=28, no_wrap=True)
        tbl.add_column("Matched At", style=f"dim {COLOR_SECONDARY}", min_width=24)

        _SEV_STYLE = {
            "CRITICAL": f"bold {COLOR_ERROR}",
            "HIGH": f"bold {COLOR_ERROR}",
            "MEDIUM": f"bold {COLOR_WARNING}",
            "LOW": f"bold {COLOR_ACCENT}",
            "INFO": f"dim {COLOR_SECONDARY}",
        }

        for fnd in shown:
            info = fnd.get("info", {})
            title = info.get("name") or fnd.get("template-id", "Unknown")
            severity = (info.get("severity") or fnd.get("severity", "INFO")).upper()
            host = fnd.get("host", "")
            matched = fnd.get("matched-at", "")[:60] if fnd.get("matched-at") else ""

            sev_style = _SEV_STYLE.get(severity, f"dim {COLOR_SECONDARY}")
            sev_text = Text(severity, style=sev_style)

            tbl.add_row(sev_text, title, host, matched or "[dim]—[/dim]")

        panel = Panel(
            tbl,
            title=f"[bold {COLOR_ERROR}]⚠ Vulnerabilities Found[/bold {COLOR_ERROR}]  "
                  f"[dim]{len(findings)} total[/dim]",
            title_align="left",
            box=PANEL_BOX,
            border_style=COLOR_DIVIDER,
            padding=(0, 1),
        )
        console.print(panel)

        if trimmed > 0:
            console.print(f"  [dim]… and {trimmed} more — use [bold]--output results.json[/bold] to see all.[/dim]\n")
        else:
            console.print()
