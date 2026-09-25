"""AI Distillation Engine: Token-budgeted bundles (context.json, findings.json, js_manifest.json, prompt.md)."""

import json
from pathlib import Path
from typing import Any, Optional


class AIDistillationEngine:
    """Condenses recon discovery databases into structured, token-budgeted bundles for LLMs."""

    @staticmethod
    def export_bundle(
        target: str,
        session_dir: Path,
        output_dir: Path,
        token_budget_k: int = 32,
    ) -> Path:
        """Generates the four core AI bundle files in output_dir."""
        ai_dir = output_dir / "ai"
        ai_dir.mkdir(parents=True, exist_ok=True)

        # 1. Extract live hosts and endpoints
        live_hosts = []
        js_files = []
        artifacts_dir = session_dir / "artifacts"

        for art in artifacts_dir.glob("*.jsonl"):
            with open(art, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        url = data.get("url")
                        if url:
                            live_hosts.append({
                                "url": url,
                                "status": data.get("status_code"),
                                "title": data.get("title"),
                                "tech": data.get("tech", []),
                            })
                            if url.endswith(".js"):
                                js_files.append(url)
                    except Exception:
                        continue

        # 2. Extract findings
        findings = []
        for art in artifacts_dir.glob("*findings*.jsonl"):
            with open(art, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    try:
                        fnd = json.loads(line)
                        findings.append({
                            "title": fnd.get("info", {}).get("name") or fnd.get("title", "Unknown"),
                            "severity": fnd.get("info", {}).get("severity", "INFO").upper(),
                            "host": fnd.get("host"),
                            "matched_at": fnd.get("matched-at"),
                            "curl_poc": fnd.get("curl-command"),
                        })
                    except Exception:
                        continue

        # Write context.json
        context_data = {
            "target": target,
            "token_budget": f"{token_budget_k}k",
            "summary": {
                "live_endpoints_discovered": len(live_hosts),
                "javascript_assets": len(js_files),
                "total_findings": len(findings),
            },
            "high_value_surfaces": live_hosts[:200],  # Budgeted slice
        }
        with open(ai_dir / "context.json", "w", encoding="utf-8") as f:
            json.dump(context_data, f, indent=2)

        # Write findings.json
        with open(ai_dir / "findings.json", "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)

        # Write js_manifest.json
        with open(ai_dir / "js_manifest.json", "w", encoding="utf-8") as f:
            json.dump(js_files, f, indent=2)

        # Write prompt.md
        prompt_content = f"""# Security Assessment Directive for Target: {target}

You are acting as a Principal Application Security Architect reviewing automated reconnaissance data.

## Objectives
1. Inspect `context.json` for high-value attack surfaces, admin consoles, and authentication routes.
2. Review `findings.json` for confirmed vulnerabilities and CVEs with actionable proof-of-concepts.
3. Review the endpoints listed in `js_manifest.json` for exposed internal routes, API keys, and sensitive business logic.

## Desired Output
Provide an executive risk summary, top 3 highest-impact exploitation scenarios, and concrete remediation steps.
"""
        with open(ai_dir / "prompt.md", "w", encoding="utf-8") as f:
            f.write(prompt_content)

        return ai_dir
