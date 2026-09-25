"""Output Writer: Saves scan results to disk in JSON, Markdown, or CSV.

Called when --output <path> is passed to `astrarecon scan`.
The format is auto-detected from the file extension unless --output-format
is explicitly specified.
"""

from __future__ import annotations

import csv
import json
import re
from enum import Enum
from pathlib import Path

from astrarecon.core.reports.result_renderer import ScanResults


class OutputFormat(str, Enum):
    JSON = "json"
    MARKDOWN = "md"
    CSV = "csv"

    @classmethod
    def detect(cls, path: Path) -> "OutputFormat":
        """Detect format from file extension, defaulting to JSON."""
        ext = path.suffix.lstrip(".").lower()
        mapping = {"json": cls.JSON, "md": cls.MARKDOWN, "markdown": cls.MARKDOWN, "csv": cls.CSV}
        return mapping.get(ext, cls.JSON)


class OutputWriter:
    """Writes ScanResults to disk in the requested format."""

    @staticmethod
    def write(results: ScanResults, output_path: Path, fmt: OutputFormat | None = None) -> Path:
        """Write results and return the resolved output path."""
        output_path = output_path.expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if fmt is None:
            fmt = OutputFormat.detect(output_path)

        if fmt == OutputFormat.JSON:
            OutputWriter._write_json(results, output_path)
        elif fmt == OutputFormat.MARKDOWN:
            OutputWriter._write_markdown(results, output_path)
        elif fmt == OutputFormat.CSV:
            OutputWriter._write_csv(results, output_path)

        return output_path

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------
    @staticmethod
    def _write_json(results: ScanResults, path: Path) -> None:
        data = {
            "target": results.target,
            "summary": {
                "subdomains": results.subdomain_count,
                "live_hosts": results.live_host_count,
                "findings": results.finding_count,
            },
            "subdomains": results.subdomains,
            "live_hosts": results.live_hosts,
            "findings": results.findings,
        }
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------
    @staticmethod
    def _write_markdown(results: ScanResults, path: Path) -> None:
        lines: list[str] = []

        lines.append(f"# AstraRecon — {results.target}\n")
        lines.append(f"**Subdomains:** {results.subdomain_count}  "
                     f"**Live Hosts:** {results.live_host_count}  "
                     f"**Findings:** {results.finding_count}\n")
        lines.append("")

        # Subdomains
        lines.append("## Subdomains\n")
        if results.subdomains:
            lines.append("| # | Subdomain |")
            lines.append("| --- | --- |")
            for i, sub in enumerate(results.subdomains, 1):
                lines.append(f"| {i} | `{sub}` |")
        else:
            lines.append("_No subdomains discovered._")
        lines.append("")

        # Live Hosts
        lines.append("## Live HTTP Hosts\n")
        if results.live_hosts:
            lines.append("| URL | Status | Title | Technologies |")
            lines.append("| --- | --- | --- | --- |")
            for row in results.live_hosts:
                url = row.get("url") or row.get("host", "")
                status = str(row.get("status_code", ""))
                title = (row.get("title") or "").strip().replace("|", "\\|")[:60]
                tech = row.get("tech") or row.get("technologies") or []
                tech_str = ", ".join(str(t) for t in tech[:4]) if isinstance(tech, list) else str(tech)
                lines.append(f"| `{url}` | {status} | {title} | {tech_str} |")
        else:
            lines.append("_No live hosts detected._")
        lines.append("")

        # Findings
        lines.append("## Vulnerability Findings\n")
        if results.findings:
            lines.append("| Severity | Finding | Host | Matched At |")
            lines.append("| --- | --- | --- | --- |")
            for fnd in results.findings:
                info = fnd.get("info", {})
                title = (info.get("name") or fnd.get("template-id", "Unknown")).replace("|", "\\|")
                severity = (info.get("severity") or fnd.get("severity", "INFO")).upper()
                host = fnd.get("host", "")
                matched = (fnd.get("matched-at") or "").replace("|", "\\|")[:60]
                lines.append(f"| **{severity}** | {title} | `{host}` | {matched} |")
        else:
            lines.append("_No vulnerabilities detected._")
        lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------
    @staticmethod
    def _write_csv(results: ScanResults, path: Path) -> None:
        """Writes a multi-section CSV (subdomains, live hosts, findings) into one file."""
        rows: list[list[str]] = []

        rows.append(["## SUBDOMAINS"])
        rows.append(["#", "subdomain"])
        for i, sub in enumerate(results.subdomains, 1):
            rows.append([str(i), sub])

        rows.append([])
        rows.append(["## LIVE HOSTS"])
        rows.append(["url", "status_code", "title", "technologies"])
        for row in results.live_hosts:
            url = row.get("url") or row.get("host", "")
            status = str(row.get("status_code", ""))
            title = (row.get("title") or "").strip()
            tech = row.get("tech") or row.get("technologies") or []
            tech_str = "|".join(str(t) for t in tech[:6]) if isinstance(tech, list) else str(tech)
            rows.append([url, status, title, tech_str])

        rows.append([])
        rows.append(["## FINDINGS"])
        rows.append(["severity", "name", "host", "matched_at", "curl_poc"])
        for fnd in results.findings:
            info = fnd.get("info", {})
            title = info.get("name") or fnd.get("template-id", "")
            severity = (info.get("severity") or fnd.get("severity", "INFO")).upper()
            host = fnd.get("host", "")
            matched = fnd.get("matched-at", "")
            curl = fnd.get("curl-command", "")
            rows.append([severity, title, host, matched, curl])

        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            writer.writerows(rows)
