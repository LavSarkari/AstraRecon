<p align="center">
  <img src="logo.png" width="360" alt="AstraRecon Logo" />
</p>

<h1 align="center">AstraRecon</h1>

<p align="center">
  <strong>Visual Recon Workflow Engine</strong><br>
  <em>Linux-first, DAG-orchestrated reconnaissance with persistent sessions, CAS caching, and AI-ready exports.</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/astrarecon/"><img src="https://img.shields.io/pypi/v/astrarecon?color=1DA1FF&style=flat-square" alt="PyPI Version"/></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20WSL-1DA1FF?style=flat-square" alt="Linux | WSL"/>
  <img src="https://img.shields.io/badge/Architecture-DAG%20(Kahn's%20Sort)-22C55E?style=flat-square" alt="DAG Architecture"/>
  <img src="https://img.shields.io/badge/UI-Rich%20Live-1DA1FF?style=flat-square" alt="Rich Live UI"/>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-F59E0B?style=flat-square" alt="License: MIT"/></a>
</p>

---

## What is AstraRecon?

**AstraRecon** is not another wrapper around security binaries. It is an autonomous, graph-based **recon workflow engine** built for modern security engineers, red teams, and bug hunters.

It executes complex fan-in and fan-out reconnaissance pipelines using a DAG scheduler — no terminal spam, no lost state, no redundant re-execution.

---

## Highlights

| Feature | Description |
| :--- | :--- |
| **DAG Execution** | Concurrent node scheduling via Kahn's topological sort with cycle rejection and dynamic ready-frontier dispatch |
| **Persistent Sessions** | Every node transition is checkpointed atomically — resume interrupted scans instantly |
| **CAS Caching** | SHA-256 blob store keyed on tool version + config + input hash prevents redundant re-scans |
| **Rich Live UI** | Single in-place viewport with live status icons, timers, and artifact yield counters — zero scroll spam |
| **Plugin Manifests** | Chain Go binaries, Python tools, and shell scripts via declarative YAML — no code changes needed |
| **AI Distillation** | Compresses raw scan output into token-budgeted prompt bundles ready for GPT-4o, Claude, and Gemini |

---

## Interface Tour

### Startup Screen — `astrarecon`

```text
╭───────────────────────────────────────────────────────────────╮
│                                                               │
│   ASTRARECON                                                  │
│   Visual Recon Workflow Engine                                │
│   ────────────────────────────────────────────────────────    │
│   Engine          v0.1.0                                      │
│   Platform        Linux • WSL (x86_64)                        │
│   Sessions        8 recorded (• Last: example.com (12m ago))  │
│   Cache           14.2 MB (CAS)                               │
│   Plugins         9 ready • 3 missing                         │
│   ────────────────────────────────────────────────────────    │
│   Installed Plugins                                           │
│                                                               │
│   ✓ subfinder               ✓ dnsx                            │
│   ✓ assetfinder             ✓ httpx                           │
│   ✓ amass                   ✓ naabu                           │
│   ✓ katana                  ○ linkfinder                      │
│   ✓ nuclei                  ✓ dalfox                          │
│   ✓ gau                     ✓ waybackurls                     │
│   ────────────────────────────────────────────────────────    │
│   Quick Commands                                              │
│                                                               │
│   astrarecon scan example.com                                 │
│   astrarecon doctor                                           │
│   astrarecon plugins list                                     │
│   astrarecon sessions list                                    │
│                                                               │
╰───────────────────────────────────────────────────────────────╯
```

### Live Scan Dashboard — `astrarecon scan <target>`

```text
╭─ ASTRARECON ─ example.com [00:18] ─────────────────────────╮
│                                                            │
│  ✔  Target Input       Success         0.0s       1 items  │
│  ✔  Scope Guard        Success         0.0s       1 items  │
│  ✔  Subfinder          Success         4.2s     142 items  │
│  ✔  Assetfinder        Success         2.8s      88 items  │
│  ✔  Amass              Success         7.4s     194 items  │
│  ✔  Union Dedupe       Success         0.1s     216 items  │
│  ▶  DNSX               Running         3.1s                │
│  ●  HTTPX              Waiting         --                  │
│                                                            │
╰────────────────────────────────────────────────────────────╯
```

### Post-Scan Summary

```text
╭──────────────────────────────────────────────────────────────╮
│                                                              │
│   ✔ Scan Completed for example.com in 00m 24s                │
│   ──────────────────────────────────────────────────         │
│   Session ID          2026-09-26-001-example-com             │
│   Subdomains          216                                    │
│   Live HTTP Hosts     48                                     │
│   Vulnerabilities     3                                      │
│   AI Export Bundle    ~/.astrarecon/sessions/.../exports     │
│                                                              │
│   Run 'astrarecon export ai 2026-09-26-001-example-com'      │
│   to inspect the prompt bundle.                              │
│                                                              │
╰──────────────────────────────────────────────────────────────╯
```

---

## Plugin Ecosystem

AstraRecon ships with **13 built-in plugin manifests** covering the full recon lifecycle:

| Stage | Plugin | Description |
| :--- | :--- | :--- |
| **Subdomain Enumeration** | `subfinder` | Fast passive subdomain enumeration |
| | `assetfinder` | Passive asset discovery via cert transparency archives |
| | `amass` | Deep network mapping & recursive DNS discovery |
| | `subenum` | Automated subdomain harvesting shell script |
| **DNS Resolution** | `dnsx` | Multi-resolver DNS probing & wildcard validation |
| **HTTP Probing** | `httpx` | Live web server probing, title & tech detection |
| **Port Scanning** | `naabu` | Fast TCP SYN/connect port scanner |
| **Historical & Crawling** | `gau` | Wayback Machine, AlienVault & CommonCrawl URLs |
| | `waybackurls` | Historical endpoints from archive.org |
| | `katana` | Headless active crawler & JavaScript parser |
| **JS Endpoint Discovery** | `linkfinder` | Python AST endpoint extraction from `.js` files |
| **Vulnerability Scanning** | `nuclei` | Fast template-based vulnerability assessment |
| **XSS Testing** | `dalfox` | Parameter analysis & DOM/reflected XSS detection |

### Custom Plugins

Drop a `plugin.yaml` into `~/.astrarecon/plugins/<name>/` and it is auto-discovered immediately — no restart required.

```yaml
# ~/.astrarecon/plugins/mytools/plugin.yaml
name: mytools
binary: mytools
version_flag: --version
install:
  method: go
  package: github.com/example/mytools@latest
inputs:
  - name: target
    type: domain
outputs:
  - name: results
    type: file
```

---

## Installation

### Requirements

- Python **3.11+**
- Linux (Ubuntu, Debian, Kali, Arch) or **WSL2**

### From PyPI

Using `uv` (recommended):

```bash
uv tool install astrarecon
```

Using `pipx`:

```bash
pipx install astrarecon
```

Using `pip`:

```bash
python3.11 -m pip install astrarecon
```

### From Source

```bash
git clone https://github.com/LavSarkari/AstraRecon.git
cd AstraRecon

python3.11 -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"
```

### Bootstrap Missing Tools

After install, let AstraRecon download and compile all missing security binaries into `~/.astrarecon/bin/`:

```bash
astrarecon doctor --install-missing
```

---

## Quick Start

```bash
# Run a full recon pipeline
astrarecon scan example.com

# Save results to a file — JSON, Markdown, or CSV
astrarecon scan example.com --output results.json
astrarecon scan example.com --output report.md
astrarecon scan example.com --output data.csv

# Resume an interrupted scan — no re-running finished nodes
astrarecon scan example.com --resume 2026-09-26-001-example-com

# Scan only newly discovered assets since the last baseline
astrarecon scan example.com --diff-only

# Check environment and tool health
astrarecon doctor

# Self-update to the latest stable release
astrarecon update
astrarecon update --check            # dry-run: check only, don't install
astrarecon update --source github    # bleeding-edge from GitHub main

# List and manage sessions
astrarecon sessions list
astrarecon sessions inspect <session-id>

# Export results from any completed session
astrarecon export results <session-id>
astrarecon export results <session-id> --output report.md
astrarecon export ai <session-id>    # regenerate AI bundle

# Inspect plugins and CAS storage
astrarecon plugins list
astrarecon cache stats
```

---

## Results & Exports

### Scan Results

After every scan, AstraRecon renders real results in the terminal automatically — no AI export required:

- **Subdomains table** — full deduplicated list from all enumeration tools
- **Live HTTP hosts** — URL, status code, title, and detected technologies
- **Vulnerability findings** — severity, template name, host, and matched location

Use `--no-results` to skip the tables and show the summary card only.

### Save Results to a File

```bash
astrarecon scan example.com --output results.json   # full JSON
astrarecon scan example.com --output report.md      # Markdown tables
astrarecon scan example.com --output data.csv       # CSV
```

Format is auto-detected from the file extension. Override with `--output-format json|md|csv`.

### Export from a Past Session

```bash
# Show results for any completed session
astrarecon export results <session-id>
astrarecon export results <session-id> --output report.md

# Re-generate the AI distillation bundle
astrarecon export ai <session-id>
```

### AI Distillation Bundle

Every completed scan also generates a structured AI export bundle under `<session_dir>/exports/ai/`:

| File | Contents |
| :--- | :--- |
| `context.json` | Target scope, CIDR ranges, root domains, and environment fingerprint |
| `findings.json` | Triaged vulnerabilities by severity with reproducible `curl` commands |
| `js_manifest.json` | Extracted endpoints, hardcoded tokens, and API routes from JavaScript files |
| `prompt.md` | Pre-populated system prompt with distilled attack surface data for LLM triage |

Designed to feed **GPT-4o**, **Claude 3.5 Sonnet**, and **Gemini 1.5 Pro** without blowing token budgets.

---

## Documentation

| Document | Description |
| :--- | :--- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | DAG scheduler, Kahn's algorithm, process isolation, and CAS caching |
| [SPECIFICATION.md](SPECIFICATION.md) | Plugin manifest schema, workflow YAML syntax, and session state machines |
| [ROADMAP.md](ROADMAP.md) | Development milestones, deliverables, and future horizons |

---

## Development

```bash
# Run the test suite
python -m pytest -v

# Build distribution artifacts
python -m build

# Validate distributions
python -m twine check dist/*
```

CI runs the full test suite and validates distribution artifacts on every push and pull request.

---

## Contributing

Pull requests are welcome. For significant changes, open an issue first to discuss what you'd like to change. Ensure all tests pass and new functionality is covered before submitting a PR.

---

## License

MIT © 2026 [LavSarkari](https://github.com/LavSarkari)

---

<p align="center">
  <sub>Built for security engineers who want reconnaissance to behave like a workflow — not a pile of shell scripts.</sub>
</p>
