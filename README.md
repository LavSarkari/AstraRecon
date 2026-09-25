<p align="center">
  <img src="logo.png" width="360" alt="AstraRecon Logo" />
</p>

<h1 align="center">ASTRARECON</h1>
<p align="center">
  <strong>Visual Recon Workflow Engine</strong><br>
  <em>Linux-first, DAG-orchestrated reconnaissance engine with persistent sessions, Content-Addressed Storage, and AI-ready exports.</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/astrarecon/"><img src="https://img.shields.io/pypi/v/astrarecon?color=1DA1FF&style=flat-square" alt="PyPI Version"/></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20WSL-1DA1FF?style=flat-square" alt="Linux | WSL"/>
  <img src="https://img.shields.io/badge/Architecture-DAG%20%28Kahn's%20Sort%29-22C55E?style=flat-square" alt="DAG Architecture"/>
  <img src="https://img.shields.io/badge/UI-Rich%20Live-1DA1FF?style=flat-square" alt="Rich Live UI"/>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-F59E0B?style=flat-square" alt="License: MIT"/></a>
</p>

---

## Overview

**AstraRecon** is not just another wrapper around security binaries. It is an autonomous, graph-based **recon workflow engine** designed for modern security engineers, red teams, and bug hunters. 

Built with the speed of **uv**, the minimalism of **GitHub CLI (`gh`)**, and the ergonomics of **pnpm**, AstraRecon executes complex fan-in and fan-out reconnaissance pipelines without terminal spam, state loss, or redundant re-execution.

---

## Key Highlights

- **DAG-Driven Pipeline Execution:** Schedulable nodes execute concurrently using Kahn's topological sort with automatic cycle rejection and dynamic ready-frontier dispatch.
- **Minimal, Persistent CLI UX:** Zero terminal scroll spam. In-place live updating panel powered by Python `rich.Live` that refreshes in a single rounded viewport.
- **Content-Addressed Storage (CAS):** SHA256-indexed blob store (`~/.astrarecon/cache/`) prevents expensive re-scans by verifying tool version, configuration, and input hash.
- **Crash-Resilient State Machine:** Every node transition is checkpointed to atomic disk journals. Resume interrupted scans instantly with `astrarecon scan <target> --resume <session_id>`.
- **Plug-and-Play Script Support:** Seamlessly chain Go binaries (`subfinder`, `httpx`), Python tools (`LinkFinder`), and custom shell scripts (`subenum.sh`) using declarative YAML manifests.
- **AI Distillation Engine:** Automatically compresses gigabytes of recon outputs into token-budgeted prompt bundles (`context.json`, `findings.json`, `js_manifest.json`, `prompt.md`) ready for LLM triage.

---

## Interface Tour

### 1. Startup Screen (`astrarecon`)
When launched without arguments, AstraRecon queries system state and renders a clean, rounded telemetry card:

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
│   Type 'astrarecon scan example.com' to begin.                │
│                                                               │
╰───────────────────────────────────────────────────────────────╯
```

### 2. Live Scan Dashboard (`astrarecon scan <target>`)
During active execution, the terminal switches to an in-place live panel with real-time status icons, timers, and artifact yield counters:

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

### 3. Post-Scan Completion Summary
Upon graph completion, AstraRecon renders an audit card detailing discovered attack surfaces and the AI distillation bundle path:

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
│   Run 'astrarecon export ai 2026-09-26-001-example-com' to   │
│   inspect prompt bundle.                                     │
│                                                              │
╰──────────────────────────────────────────────────────────────╯
```

---

## Supported Ecosystem Plugins

AstraRecon ships with 13 out-of-the-box plugin manifests covering the complete recon lifecycle:

| Stage | Plugin | Binary | Description |
| :--- | :--- | :--- | :--- |
| **Subdomain Enumeration** | `subfinder` | `subfinder` | Fast passive subdomain enumeration |
| | `assetfinder` | `assetfinder` | Passive asset finding via cert archives |
| | `amass` | `amass` | Deep network mapping & recursive DNS discovery |
| | `subenum` | `subenum` | Automated subdomain harvesting shell script |
| **DNS Resolution** | `dnsx` | `dnsx` | Multi-resolver DNS probing & wildcard validation |
| **HTTP Probing** | `httpx` | `httpx` | Live web server probing, title & tech detection |
| **Port Scanning** | `naabu` | `naabu` | Fast TCP SYN/connect port scanner |
| **Historical & Crawling** | `gau` | `gau` | Wayback Machine, AlienVault & CommonCrawl URLs |
| | `waybackurls` | `waybackurls` | Historical endpoints from archive.org |
| | `katana` | `katana` | Headless, active crawler & JavaScript parser |
| **JS Endpoint Discovery** | `linkfinder` | `linkfinder` | Python AST endpoint extraction from `.js` files |
| **Vulnerability Scanning**| `nuclei` | `nuclei` | Fast template-based vulnerability assessment |
| **XSS Parameter Testing** | `dalfox` | `dalfox` | Parameter analysis & DOM/reflected XSS testing |

---

## Adding Custom Scripts

You can turn any bash script, python tool, or binary into a first-class AstraRecon node in seconds. Custom plugins placed in `~/.astrarecon/plugins/<name>/plugin.yaml` are auto-discovered immediately.

---

## Installation & Setup

### Requirements
- Python 3.11+
- Linux (Ubuntu, Debian, Kali, Arch) or WSL2 (Windows Subsystem for Linux)

### Option 1: Install from PyPI
```bash
pip install astrarecon
```

### Option 2: Install from Source (Recommended for Contributors)
```bash
# Clone the repository
git clone https://github.com/LavSarkari/AstraRecon.git
cd AstraRecon

# Create virtual environment and install in editable mode
python -m venv .venv
source .venv/bin/activate  # Or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

### Automatic Tool Remediation
AstraRecon can automatically download and compile all missing external security binaries (`subfinder`, `nuclei`, `httpx`, `subenum`, etc.) directly into `~/.astrarecon/bin/`:
```bash
astrarecon doctor --install-missing
```

---

## Quick Start

### 1. Launch a Reconnaissance Pipeline
```bash
astrarecon scan example.com
```

### 2. Resume an Interrupted Scan
If a scan was stopped via `Ctrl+C` or a network glitch, resume immediately without re-running finished nodes:
```bash
astrarecon scan example.com --resume 2026-09-26-001-example-com
```

### 3. Continuous Delta Recon
Scan only newly discovered assets compared to previous baselines:
```bash
astrarecon scan example.com --diff-only
```

### 4. Inspect Plugin Ecosystem
```bash
astrarecon plugins list
```

### 5. Inspect CAS Storage
```bash
astrarecon cache stats
```

---

## AI-Ready Export Bundle

AstraRecon is purpose-built to feed frontier LLMs (Claude 3.5 Sonnet, Gemini 1.5 Pro, GPT-4o) without blowing token context budgets. Every scan automatically generates a structured export bundle under `<session_dir>/exports/`:

- `context.json`: Target scope, CIDR ranges, root domains, and environmental fingerprint.
- `findings.json`: Triaged vulnerabilities categorized by severity with reproducible `curl` commands.
- `js_manifest.json`: Extracted endpoints, hardcoded tokens, and API routes discovered in JavaScript files.
- `prompt.md`: A system prompt pre-populated with distilled attack surface data ready to copy-paste into your AI agent of choice.

---

## Documentation Index

- [ARCHITECTURE.md](ARCHITECTURE.md) — Comprehensive technical architecture, DAG scheduler, Kahn's algorithm, process isolation, and CAS caching.
- [SPECIFICATION.md](SPECIFICATION.md) — Declarative schemas, plugin manifest specification, workflow YAML syntax, and session state machines.
- [ROADMAP.md](ROADMAP.md) — Development milestones, deliverables, and future horizons.

---

<p align="center">
  <sub>Built with precision for bug bounty hunters, penetration testers, and offensive security engineers.</sub>
</p>
