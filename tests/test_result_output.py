"""Tests for result renderer and output writer."""

import json
import tempfile
from pathlib import Path

import pytest

from astrarecon.core.reports.result_renderer import ScanResultLoader, ScanResults, ScanResultsRenderer
from astrarecon.core.reports.output_writer import OutputFormat, OutputWriter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_session(tmp_path: Path, subdomains: list[str], live_hosts: list[dict], findings: list[dict]) -> Path:
    """Creates a minimal fake session directory with artifact files."""
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()

    if subdomains:
        (artifacts / "union_dedupe.txt").write_text("\n".join(subdomains), encoding="utf-8")

    if live_hosts:
        lines = "\n".join(json.dumps(h) for h in live_hosts)
        (artifacts / "httpx_output.jsonl").write_text(lines, encoding="utf-8")

    if findings:
        lines = "\n".join(json.dumps(f) for f in findings)
        (artifacts / "nuclei_findings.jsonl").write_text(lines, encoding="utf-8")

    return tmp_path


SAMPLE_SUBDOMAINS = ["api.example.com", "admin.example.com", "dev.example.com"]
SAMPLE_HOSTS = [
    {"url": "https://api.example.com", "status_code": 200, "title": "API Gateway", "tech": ["nginx", "Python"]},
    {"url": "https://admin.example.com", "status_code": 401, "title": "Admin Panel", "tech": ["Apache"]},
]
SAMPLE_FINDINGS = [
    {"info": {"name": "Open Redirect", "severity": "medium"}, "host": "api.example.com", "matched-at": "/redirect?url="},
    {"info": {"name": "XSS Reflected", "severity": "high"}, "host": "admin.example.com", "matched-at": "/?q=<script>"},
]


# ---------------------------------------------------------------------------
# ScanResultLoader
# ---------------------------------------------------------------------------

class TestScanResultLoader:
    def test_loads_subdomains(self, tmp_path):
        session = make_session(tmp_path, SAMPLE_SUBDOMAINS, [], [])
        results = ScanResultLoader.load(session, "example.com")
        assert results.subdomain_count == 3
        assert "api.example.com" in results.subdomains

    def test_loads_live_hosts(self, tmp_path):
        session = make_session(tmp_path, [], SAMPLE_HOSTS, [])
        results = ScanResultLoader.load(session, "example.com")
        assert results.live_host_count == 2
        assert results.live_hosts[0]["url"] == "https://api.example.com"

    def test_loads_findings(self, tmp_path):
        session = make_session(tmp_path, [], [], SAMPLE_FINDINGS)
        results = ScanResultLoader.load(session, "example.com")
        assert results.finding_count == 2

    def test_empty_artifacts_dir(self, tmp_path):
        (tmp_path / "artifacts").mkdir()
        results = ScanResultLoader.load(tmp_path, "example.com")
        assert results.subdomain_count == 0
        assert results.live_host_count == 0
        assert results.finding_count == 0

    def test_missing_artifacts_dir(self, tmp_path):
        results = ScanResultLoader.load(tmp_path, "example.com")
        assert results.subdomain_count == 0


# ---------------------------------------------------------------------------
# OutputWriter
# ---------------------------------------------------------------------------

class TestOutputWriter:
    def _make_results(self) -> ScanResults:
        r = ScanResults(target="example.com")
        r.subdomains = SAMPLE_SUBDOMAINS
        r.live_hosts = SAMPLE_HOSTS
        r.findings = SAMPLE_FINDINGS
        return r

    def test_write_json(self, tmp_path):
        out = tmp_path / "results.json"
        OutputWriter.write(self._make_results(), out)
        data = json.loads(out.read_text())
        assert data["target"] == "example.com"
        assert data["summary"]["subdomains"] == 3
        assert len(data["subdomains"]) == 3
        assert len(data["live_hosts"]) == 2
        assert len(data["findings"]) == 2

    def test_write_markdown(self, tmp_path):
        out = tmp_path / "results.md"
        OutputWriter.write(self._make_results(), out)
        content = out.read_text()
        assert "# AstraRecon — example.com" in content
        assert "## Subdomains" in content
        assert "## Live HTTP Hosts" in content
        assert "## Vulnerability Findings" in content
        assert "api.example.com" in content

    def test_write_csv(self, tmp_path):
        out = tmp_path / "results.csv"
        OutputWriter.write(self._make_results(), out)
        content = out.read_text()
        assert "## SUBDOMAINS" in content
        assert "## LIVE HOSTS" in content
        assert "## FINDINGS" in content
        assert "api.example.com" in content

    def test_format_autodetect_json(self, tmp_path):
        out = tmp_path / "out.json"
        path = OutputWriter.write(self._make_results(), out)
        data = json.loads(path.read_text())
        assert "target" in data

    def test_format_autodetect_md(self, tmp_path):
        out = tmp_path / "out.md"
        OutputWriter.write(self._make_results(), out)
        assert "# AstraRecon" in out.read_text()

    def test_explicit_format_override(self, tmp_path):
        # Force JSON even with .txt extension
        out = tmp_path / "results.txt"
        OutputWriter.write(self._make_results(), out, fmt=OutputFormat.JSON)
        data = json.loads(out.read_text())
        assert data["target"] == "example.com"

    def test_creates_parent_dirs(self, tmp_path):
        out = tmp_path / "deep" / "nested" / "results.json"
        OutputWriter.write(self._make_results(), out)
        assert out.exists()


# ---------------------------------------------------------------------------
# OutputFormat
# ---------------------------------------------------------------------------

class TestOutputFormat:
    def test_detect_json(self):
        assert OutputFormat.detect(Path("out.json")) == OutputFormat.JSON

    def test_detect_md(self):
        assert OutputFormat.detect(Path("report.md")) == OutputFormat.MARKDOWN

    def test_detect_markdown(self):
        assert OutputFormat.detect(Path("report.markdown")) == OutputFormat.MARKDOWN

    def test_detect_csv(self):
        assert OutputFormat.detect(Path("data.csv")) == OutputFormat.CSV

    def test_detect_fallback(self):
        assert OutputFormat.detect(Path("out.txt")) == OutputFormat.JSON
