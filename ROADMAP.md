# AstraRecon — Development Roadmap

> **Current Version:** v0.2.0 (Interactive Console, Tool Registration & Dynamic Pipeline)  
> **Sequencing Model:** Dependency-Driven Architecture with Council-Validated "Rule of Three" Staging

---

## Phase Breakdown & Progress Status

```text
[X] Phase 1: Core Foundation, Domain Models & Kahn's Scheduler
    │
[X] Phase 2: The "Rule of Three" Pipeline (Subfinder ──► DNSX ──► HTTPX)
    │
[X] Phase 3: Persistent Sessions, Checkpointing & Two-Stage Signal Guard
    │
[X] Phase 4: Content-Addressed Store (CAS) & Freshness Policies
    │
[X] Phase 5: Built-in Guardrail Nodes (Normalizer, Scope, Dedupe, Wildcard)
    │
[X] Phase 6: System Doctor, Diagnostic Inspector & Environment Check
    │
[X] Phase 7: Continuous Delta Engine & Lightweight Diffing
    │
[X] Phase 8: Plugin Library Expansion (12 Tools + Custom Script Support)
    │
[X] Phase 9: AI Distillation Bundle & Token-Budgeted Exports
    │
[X] Phase 10: Hermes/GitHub-CLI/uv-Grade Rich CLI UX (Startup & Live In-Place Panel)
```

---

## Detailed Deliverables by Phase

### Phase 1: Core Foundation, Domain Models & Kahn's Scheduler [COMPLETED]
- [x] Initialize Python package scaffolding (`pyproject.toml`, Typer CLI framework).
- [x] Implement Recon Type Ontology (`TargetDomain`, `FQDN`, `IPAddress`, `HTTPUrl`, `Finding`, `NetworkCIDR`, `ASN`).
- [x] Implement Pydantic domain models for `Node`, `Edge`, `Workflow`, `Session`, and `Checkpoint`.
- [x] Implement Kahn’s Algorithm for topological sorting, cycle detection, and ready-frontier dependency scheduling.
- [x] Write comprehensive unit tests proving topological sorting, cycle rejection, and execution frontiers.

### Phase 2: The "Rule of Three" Pipeline Validation [COMPLETED]
- [x] Implement external Process Runner with process-group isolation (`os.setsid`).
- [x] Build plugin wrappers for the Core Tools:
  - `subfinder` (Passive Subdomain Discovery)
  - `dnsx` (DNS Validation & IP Resolution)
  - `httpx` (Live Endpoint Discovery & Tech Fingerprinting)
- [x] Validate end-to-end execution of `TargetDomain` $\rightarrow$ `subfinder` $\rightarrow$ `dnsx` $\rightarrow$ `httpx` via file-spooled streaming.

### Phase 3: Persistent Sessions & Signal Guard [COMPLETED]
- [x] Session directory manager (`session.json`, `workflow.json`, atomic directories).
- [x] Session lifecycle state machine (`CREATED` → `RUNNING` → `CHECKPOINTED` → `COMPLETED` / `INTERRUPTED` / `FAILED`).
- [x] Environment fingerprint recorder (`fingerprint.json`) capturing OS, kernel, Go, Python, and tool versions.
- [x] Signal escalation and graceful buffer flushes on interrupt.
- [x] Session resumption via `astrarecon scan <target> --resume <session_id>`.

### Phase 4: Content-Addressed Store (CAS) & Freshness Cache [COMPLETED]
- [x] Content-addressed blob store with SHA256 hashed file paths (`blobs/xx/xxxx`).
- [x] Execution cache key calculation:
  $$\text{SHA256}(\text{plugin\_id} \parallel \text{plugin\_version} \parallel \text{tool\_version} \parallel \text{config\_hash} \parallel \text{input\_artifact\_hash})$$
- [x] SQLite WAL cache index tracking creation timestamps, TTL expiration, and line counts.
- [x] Cache policy evaluation (`fresh` vs `none`).

### Phase 5: Built-in Guardrail Nodes [COMPLETED]
- [x] **`builtin.target_input`:** Ingests raw input strings, normalizes target domains, strips protocols.
- [x] **`builtin.scope_guard`:** Filters out-of-scope discoveries into quarantine directories.
- [x] **`builtin.union_dedupe`:** Streaming deduplicator with partial-failure tolerance.
- [x] **`builtin.wildcard_detector`:** Injects high-entropy DNS probes to detect and quarantine wildcard traps.

### Phase 6: System Doctor & Environment Diagnostics [COMPLETED]
- [x] `astrarecon doctor` verifying host OS, PATH, Go compiler, Python runtime, and security binaries.
- [x] Version regex detection and path mapping for all core tool dependencies.
- [x] Managed binary directory support (`~/.astrarecon/bin/`).

### Phase 7: Continuous Delta Engine & Lightweight Diffing [COMPLETED]
- [x] **`builtin.delta_engine`:** Fast set-difference calculation ($\Delta = \text{Current} \setminus \text{Baseline}$).
- [x] Continuous recon flag: `astrarecon scan <target> --diff-only`.
- [x] Track historical baselines across persistent session states.

### Phase 8: Plugin Library Expansion (12 Tools + Custom Scripts) [COMPLETED]
- [x] **Subdomains:** `subfinder`, `assetfinder`, `amass`, `subenum.sh` (custom script support)
- [x] **DNS Resolution:** `dnsx`
- [x] **HTTP Probing:** `httpx`
- [x] **Port Scanning:** `naabu`
- [x] **Historical & Crawling:** `gau`, `waybackurls`, `katana`
- [x] **JavaScript Analysis:** `linkfinder`
- [x] **Vulnerability Assessment:** `nuclei`, `dalfox`
- [x] Dynamic plugin loader scanning `default_plugins/` and user directory `~/.astrarecon/plugins/`.

### Phase 9: AI Distillation Bundle & Token-Budgeted Exports [COMPLETED]
- [x] Token-budgeted AI distillation engine generating:
  - `context.json`: Target scope, CIDR ranges, root domains, and environment fingerprints.
  - `findings.json`: Triaged vulnerabilities categorized by severity with reproducible `curl` commands.
  - `js_manifest.json`: Extracted endpoints and secrets found in JavaScript files.
  - `prompt.md`: Pre-populated system prompt ready for Claude 3.5 Sonnet / Gemini / GPT-4o triage.

### Phase 10: Hermes/GitHub-CLI/uv-Grade Rich CLI UX [COMPLETED]
- [x] Pure black background (`#000000`) and electric blue accent (`#1DA1FF`) color system.
- [x] Dynamic startup screen (`astrarecon`) inside a persistent rounded panel (`box.ROUNDED`).
- [x] Live in-place updating DAG scan panel powered by `rich.Live` (zero terminal scroll spam).
- [x] Status icons (`▶` Running, `●` Waiting, `✔` Success, `↻` Retry, `✖` Failed, `◈` Cached, `○` Skipped).
- [x] Post-scan completion summary card with discovered asset counts and AI bundle path.

---

## Future Horizon

### Version 1.1: Automated Bootstrap Installer
- One-line shell installer script for Linux and WSL (`curl -fsSL https://astrarecon.dev/install.sh | bash`).
- Automated binary downloads for missing tools into `~/.astrarecon/bin/`.
- Interactive API key configuration helper (`Chaos`, `AlienVault`, `SecurityTrails`).

### Version 2.0: The Visual Canvas (n8n for Recon)
- Lightweight Vite + React + `@xyflow/react` static SPA served directly by FastAPI.
- Live canvas monitoring with real-time node borders, counters, and xterm.js streaming logs.
- Interactive visual pipeline builder saving directly to `.astra` format.
- Scheduled scans and webhook alerting.
