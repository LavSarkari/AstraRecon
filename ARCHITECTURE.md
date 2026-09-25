# AstraRecon — Architectural Blueprint & System Design

> **Document Status:** Hardened & Council-Validated Architectural Baseline  
> **Platform Target:** Linux-first (Ubuntu, Debian, Kali, WSL2)  
> **Core Concept:** Headless, domain-agnostic DAG orchestration engine with persistent recoverable sessions, content-addressed caching, operational guardrails, lightweight delta-recon, and AI-ready exports.

---

## 1. System Vision & Core Principles

AstraRecon is a modular, deterministic reconnaissance orchestration platform. It automates authorized security assessments by orchestrating proven CLI tools rather than reimplementing scanner logic.

### Architectural Principles (Council Validated)
1. **Engine-First, Headless Decoupling:** The CLI is the primary engine. The future visual editor (an n8n-style dashboard) is purely a presentation client communicating via JSON/SSE with zero orchestration logic of its own.
2. **Domain-Agnostic Core Engine:** The scheduler and runtime know *nothing* about "subdomains" or "DNS". They only manage **Nodes, Typed Artifacts, Checkpoints, and Process Groups**. All domain logic (normalizers, wildcard detection, deduplication) lives strictly in **Built-in Nodes**.
3. **Every Execution is Recoverable:** Scans are modeled as persistent sessions with state machines and checkpointing. A scan survives terminal closures, system crashes, and machine suspension.
4. **The Zero-Config Rule:** Running `astrarecon scan example.com` requires zero flags or upfront setup. The engine silently auto-detects RAM/CPU, applies safe concurrency profiles, enables caching, and produces clean terminal output. Pro flags exist for advanced scenarios, not mandatory onboarding.
5. **Continuous Recon & Delta-Driven Execution:** Simple, low-overhead file-level set difference (`assets.added`) isolates newly discovered surfaces so heavy active tools only scan fresh assets.
6. **Defensive Guardrails as Built-in Nodes:** Safeguards (scope containment, dirty input cleanup, wildcard DNS detection, router overload prevention, disk space sentinels) are standard DAG nodes.
7. **Content-Addressed Execution & Freshness Caching:** Expensive external network operations are cached based on input data hashes, tool versions, and configurable freshness TTLs.
8. **AI-Ready Distillation:** Scan results are synthesized into token-budgeted bundles rather than dumping raw logs into an LLM context.

---

## 2. High-Level System Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                       CLI Command Layer (Typer)                        │
│   [scan]   [sessions]   [plugins]   [doctor]   [cache]   [diff]   [keys]   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                  Workflow Engine (Domain-Agnostic)                     │
│  - Directed Acyclic Graph (DAG) Topology & Cycle Detection (Kahn)      │
│  - Typed Port Contracts & Artifact Flow                                │
│  - In-Degree Frontier Resolution & Task Scheduling                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                            Plugin System                               │
│  - Declarative Manifests (plugin.yaml)                                │
│  - Decoupled Plugin Version vs. Tool Version                          │
│  - Flexible Command Vector Templates (Resilient to CLI flag updates)  │
│  - Universal Egress Mapping (Proxy routing, Bug-Bounty headers, rate)  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                Execution Engine & Resource Governor                    │
│  - Auto-detected Profiles: 'safe' (low-spec), 'default', 'beast' (VPS) │
│  - Process-Group Isolation (os.setsid) & Two-Stage Signal Guard        │
│  - Disk Space Sentinel (<1.5GB triggers auto-pause)                   │
│  - File Spooling & Streaming UNIX Pipes (No Buffer Deadlocks)          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                         Built-in Engine Nodes                          │
│  - builtin.target_input        : Input normalizer & polymorphic scope  │
│  - builtin.scope_guard         : Quarantines out-of-scope assets       │
│  - builtin.union_dedupe        : Multi-input streaming set deduplication│
│  - builtin.wildcard_detector   : High-entropy DNS sinkhole probe       │
│  - builtin.delta_engine        : Low-overhead file-diff (assets.added) │
│  - builtin.facet_filter        : Rule-based asset slicing              │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                 Session & Artifact Infrastructure                      │
│  - State Machine (CREATED → RUNNING → CHECKPOINTED → DONE)            │
│  - Content-Addressed Store (CAS) with Hash Fingerprinting             │
│  - Environment Fingerprinting (OS, Python, Go, Tool Versions)         │
│  - SQLite (WAL Mode) Canonical Store + Webhook Alert Dispatcher        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                     Reports & AI Export Layer                          │
│  - Token-Budgeted LLM Bundles (context, findings, prompt)             │
│  - cURL PoC Generator & Vulnerability Cluster Deduplicator             │
│  - JSON / Markdown / HTML Human Summaries                             │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. The "Rule of Three" Staged Tool Deployment

To prevent maintenance deadlock across 13 external tools, AstraRecon enforces a strict phased tool rollout:

```text
Phase 1 Validation Core:
TargetDomain ──► Subfinder ──► DNSX ──► HTTPX
(Harden checkpointing, CAS, SIGINT recovery, and process groups on these 3 tools first)

Phase 2 Expansion:
├── Subdomain Fan-in: Assetfinder, Amass, Subenum.sh
├── Permutations: AlterX
└── Port Discovery: Naabu

Phase 3 Active & Web Analysis:
├── Web Crawling: Katana, GAU, Waybackurls
├── JavaScript Analysis: LinkFinder
└── Vulnerability Assessment: Nuclei, Dalfox
```

---

## 4. Built-in Guardrail Nodes (Domain Logic)

Domain logic is cleanly encapsulated in built-in DAG nodes rather than polluting the core scheduler:

1. **`builtin.target_input` (Input Normalizer & Scope Classifier):**
   - Automatically sanitizes dirty input strings (strips `http://`, `https://`, trailing slashes, paths, and `*.` wildcards).
   - Ingests single domains, CIDRs, ASNs, or scope text files.
2. **`builtin.scope_guard` (Out-of-Scope Containment):**
   - Enforces scope constraints (`.*\.example\.com$`).
   - Diverts third-party cloud assets (`target.zendesk.com`, `s3.amazonaws.com`) to `quarantine/out_of_scope.txt`.
3. **`builtin.union_dedupe` (Streaming Fan-In Aggregator):**
   - Accepts multiple input streams (e.g. 4 subdomain enumeration tools).
   - Implements low-memory streaming deduplication.
   - **Partial Failure Tolerant:** If one upstream tool fails or times out, continues with remaining data and logs a non-fatal warning.
4. **`builtin.wildcard_detector` (DNS Sinkhole Probe):**
   - Fires 3 high-entropy random probes (`probe-xyz.target.com`).
   - If wildcard trap detected, flags the IP and passes `-wd` suppression flags to downstream DNS resolvers.
5. **`builtin.delta_engine` (Lightweight File Diffing):**
   - Implements simple, robust set differences: $\Delta = \text{Current} \setminus \text{Baseline}$.
   - Emits `assets.added` stream so active scanners run strictly against new surfaces.
6. **`builtin.facet_filter` (Asset Slicer):**
   - Filters HTTP/asset streams by technology, status code, or port before feeding specialized tools.

---

## 5. Execution Engine & Operational Resilience

### A. Resource Governor & Safe Defaults
- Automatically inspects host CPU and RAM on boot.
- If available RAM < 4GB, automatically defaults to `safe` profile:
  - `--profile safe`: 1 tool at a time, strictly limited threads (25 req/s). Safe for home Wi-Fi and underpowered laptops.
  - `--profile default`: 2–3 concurrent stages, balanced bursts.
  - `--profile beast`: High concurrency for multi-core VPS deployments.

### B. Network & Disk Sentinels
- **Trusted Resolver Injection:** Automatically overrides local `/etc/resolv.conf` with high-reputation resolvers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `208.67.222.222`) to prevent crashing home routers.
- **Disk Space Sentinel:** Constantly monitors the session partition. If free storage falls below **1.5 GB**, pauses active tools, writes safe checkpoints, and transitions session to `PAUSED_LOW_DISK`.

### C. Two-Stage Signal Guard & Process Groups
- All tools execute within their own OS process group (`os.setsid`).
- **First `Ctrl+C`:** Initiates polite teardown. Sends `SIGINT`, allows 5-second buffer flush, writes checkpoints, and prints resume instructions.
- **Second `Ctrl+C` (within 2s):** Immediate hard exit (`SIGKILL` to entire process groups).

---

## 6. Content-Addressed Execution & Freshness Caching

### Execution Signature Formula
$$\text{CacheKey} = \text{SHA256}(\text{PluginID} \parallel \text{PluginVersion} \parallel \text{ToolVersion} \parallel \text{ConfigHash} \parallel \text{InputArtifactHash})$$

### Freshness-Aware Cache Policies
| Stage / Tool | Cache Policy | Default TTL | Rationale |
| :--- | :--- | :--- | :--- |
| **Passive Subdomains** (`subfinder`, `assetfinder`) | Content-Addressed + Fresh | 24 Hours | DNS records change slowly; external APIs cost rate-limits. |
| **DNS Resolution** (`dnsx`) | Content-Addressed + Fresh | 12 Hours | Records may point to new IPs or expire. |
| **Port Scanning** (`naabu`) | Content-Addressed + Fresh | 6 Hours | Firewall rules and active ports fluctuate. |
| **Crawling & Spidering** (`katana`, `gau`) | Content-Addressed + Fresh | 24 Hours | URLs remain relatively consistent over short periods. |
| **Active Vulnerability Scans** (`nuclei`, `dalfox`) | Never Cache (`none`) | 0 Hours | Security state must always be validated live. |

---

## 7. Tool Setup & Environment Doctor

To eliminate "dependency hell" for users, the Doctor includes automated installation helpers:
- Inspects PATH, Go compiler, Python runtimes, and external binary versions.
- **Automated Bootstrap:** `astrarecon doctor --install-missing` downloads vetted, pre-compiled official binary releases (or invokes `pdtm`) directly to `~/.local/bin/` or `~/.astrarecon/bin/`, making installation seamless on clean Linux/WSL setups.
- **Key Wizard:** `astrarecon keys configure` provides an interactive prompt to store free community API keys (Chaos, AlienVault, SecurityTrails) in tool config paths.

---

## 8. AI-Ready Export Architecture & PoC Generation

1. **Token-Budget Allocation:** Condenses recon findings to fit within designated LLM budgets (`--budget 32k` / `64k` / `128k`).
2. **Finding Deduplication & Clustering:** Collapses duplicate parameter reflections and identical CVE alerts into canonical issue clusters.
3. **cURL PoC Generator:** Every vulnerability in `findings.json` includes the exact executable `curl` command to reproduce the issue.
4. **Export Bundle:**
   ```text
   output/<target>/ai/
     ├── context.json         # High-level architecture, cloud providers, technologies
     ├── findings.json        # Categorized vulnerabilities with cURL PoCs
     ├── js_manifest.json     # Extracted JavaScript URLs with endpoint hints
     └── prompt.md            # Structured prompt directive for downstream LLM analysis
   ```

---

## 9. CLI UX & In-Place Live Dashboard Architecture

AstraRecon implements a developer-centric CLI UX matching the visual polish of **Hermes Agent**, **GitHub CLI (`gh`)**, and **uv**.

### Terminal Stream Architecture
Traditional recon wrappers pollute the terminal with thousands of lines of unbuffered tool logs. AstraRecon routes all sub-process stdout/stderr to disk journals (`logs/<node_id>.log`) and updates terminal state exclusively via Python's **Rich** library:

```text
 ┌────────────────────────────────────────────────────────┐
 │            ExecutionEngine Event Dispatcher            │
 └──────────────────────────┬─────────────────────────────┘
                            │ (node_id, status, items)
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │              StatusPanel Model State                   │
 │  - node_statuses: dict[str, NodeExecutionStatus]       │
 │  - node_durations: dict[str, float]                    │
 │  - node_items: dict[str, int]                          │
 └──────────────────────────┬─────────────────────────────┘
                            │ render()
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │               rich.live.Live Viewport                  │
 │  - Single rounded panel (box.ROUNDED)                  │
 │  - In-place row refreshing (8 frames/sec)              │
 │  - Zero terminal scrolling spam                        │
 └────────────────────────────────────────────────────────┘
```

### UX Design Rules
1. **Black Viewport (`#000000`):** Single electric blue accent (`#1DA1FF`) without noisy rainbow gradients.
2. **Rounded Enclosures (`box.ROUNDED`):** Consistent panel framing across startup telemetry and live execution.
3. **Ontology-Driven Metric Counter:** Node artifact lines are counted dynamically and rendered alongside node status (e.g., `142 items`).
4. **Graceful Completion Handoff:** When `engine.run()` completes, the `Live` context exits cleanly, immediately rendering the final `CompletionSummaryView` card with session statistics and AI bundle paths.
