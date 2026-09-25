# AstraRecon — Technical Specifications & Schemas

> **Document Status:** Reference Specification for AstraRecon Engine & Plugins  
> **Schema Version:** 1.3.0

---

## 1. Directory Layouts

### A. Global System Directory (`~/.astrarecon/`)
```text
~/.astrarecon/
├── bin/                            # Managed binaries downloaded via doctor --install-missing
├── config.yaml                     # Global defaults, profiles, egress, webhooks
├── plugins/                        # User-installed / custom plugins
│   ├── subfinder/
│   │   ├── plugin.yaml
│   │   ├── runner.py (optional)
│   │   └── parser.py (optional)
│   └── ...
├── cache/                          # Global Content-Addressed Store (CAS)
│   ├── blobs/                      # Hashed raw artifacts: <first 2 chars>/<sha256>
│   └── index.sqlite                # Cache key index, TTLs, and reference counts
└── sessions/                       # Execution runs
    └── 2026-09-26-001-example_com/
        ├── session.json            # State machine metadata & graph progress
        ├── workflow.json           # Frozen snapshot of the executed DAG
        ├── fingerprint.json        # OS & tool environment snapshot
        ├── state.db                # SQLite: deduplicated canonical assets & findings
        ├── baseline.db             # Previous run baseline comparison data
        ├── quarantine/             # Out-of-scope quarantined items
        │   └── out_of_scope.txt
        ├── checkpoints/            # Node checkpoint descriptors
        ├── artifacts/              # Links to CAS blobs or session-specific outputs
        │   ├── subdomains.txt
        │   ├── live_hosts.jsonl
        │   └── delta_added.txt     # New assets discovered in this run
        ├── logs/                   # Isolated execution logs
        └── exports/                # Exported artifacts
            ├── ai/
            │   ├── context.json
            │   ├── findings.json   # Triaged findings with cURL PoCs
            │   ├── js_manifest.json
            │   └── prompt.md
            ├── summary.md
            └── report.json
```

---

## 2. Global Configuration Specification (`config.yaml`)

```yaml
version: 1

execution:
  default_profile: "auto"            # 'auto' (inspects hardware) | 'safe' | 'default' | 'beast'
  profiles:
    safe:
      max_concurrent_tools: 1
      max_threads_per_tool: 25
      rate_limit_per_second: 30
      enable_resolvers_override: true
    default:
      max_concurrent_tools: 3
      max_threads_per_tool: 100
      rate_limit_per_second: 150
      enable_resolvers_override: true
    beast:
      max_concurrent_tools: 8
      max_threads_per_tool: 300
      rate_limit_per_second: 1000
      enable_resolvers_override: false

egress:
  proxy: ""                          # e.g., "http://127.0.0.1:8080" or "socks5://127.0.0.1:9050"
  headers:
    - "X-Bug-Bounty: hacker_username"
    - "User-Agent: AstraRecon-Security-Audit/1.0"
  timeout_seconds: 15

notifications:
  enabled: false
  discord_webhook: ""
  slack_webhook: ""
  telegram_bot_token: ""
  telegram_chat_id: ""
  notify_on:
    - new_assets_discovered
    - high_critical_findings
    - scan_completed

guardrails:
  min_disk_free_mb: 1500            # Pause execution if free disk < 1.5GB
  max_subdomains_safety_limit: 50000# Warn and pause if wildcard explodes
  wildcard_probe_entropy_count: 3   # Probe count for wildcard DNS detection
  auto_quarantine_out_of_scope: true
  trusted_resolvers:
    - "1.1.1.1"
    - "8.8.8.8"
    - "9.9.9.9"
    - "208.67.222.222"

cache:
  enabled: true
  default_ttl_hours: 24
  max_cas_size_gb: 20
```

---

## 3. Plugin Manifest Specification (`plugin.yaml`)

Manifests declare structured metadata and flexible argument templates that remain resilient across tool updates:

```yaml
schema_version: 1
id: subfinder
name: Subfinder
plugin_version: "1.0.0"       # Version of AstraRecon integration wrapper
stage: subdomains
description: "Fast passive subdomain enumeration tool"
author: "ProjectDiscovery"

binary:
  name: subfinder
  check_args: ["-version"]
  version_regex: 'v([0-9]+\.[0-9]+\.[0-9]+)'
  default_path: "/usr/local/bin/subfinder"
  install_recipe:
    method: "github_release"   # 'github_release' | 'pdtm' | 'go_install'
    repo: "projectdiscovery/subfinder"
    binary_name: "subfinder"

inputs:
  - name: target
    type: TargetDomain
    required: true
    source: param

outputs:
  - name: subdomains
    type: FQDN
    format: text_lines
    filename: subdomains.txt

execution:
  command: subfinder
  args:
    - "-d"
    - "{inputs.target}"
    - "-silent"
    - "-all"
    - "-o"
    - "{outputs.subdomains}"
  timeout_seconds: 600
  retry_count: 1

cache:
  policy: fresh               # 'fresh' | 'none' | 'immutable'
  default_ttl_hours: 24
```

---

## 4. Built-in Engine Node Specifications

Built-in nodes execute as Python async coroutines directly within the engine:

| Node Type | Config Options | Inputs | Outputs | Description |
| :--- | :--- | :--- | :--- | :--- |
| `builtin.target_input` | `raw_input` | None | `canonical_target` | Strips schemes, wildcards, and paths; identifies target type. |
| `builtin.scope_guard` | `include`, `exclude` | `assets` | `in_scope`, `quarantine` | Regex-based asset filter routing out-of-scope discoveries to quarantine. |
| `builtin.union_dedupe` | `normalize_lower` | `inputs` (Array) | `output` | Low-memory streaming deduplication with partial failure tolerance. |
| `builtin.wildcard_detector` | `probe_count` | `hosts` | `pruned_hosts` | Issues 3 high-entropy DNS probes; suppresses wildcard trap records. |
| `builtin.delta_engine` | `baseline_id` | `current_assets` | `added`, `unchanged` | File set-difference emitting newly discovered assets for continuous recon. |
| `builtin.facet_filter` | `query` | `assets` | `matched`, `unmatched` | SQL-like filtering on technologies, status codes, and open ports. |

---

## 5. Finding Schema with cURL PoC (`findings.json`)

```json
{
  "finding_id": "fnd_7b9c2e41",
  "vuln_type": "CVE-2022-22965",
  "title": "Spring Framework RCE (Spring4Shell) via DataBinder",
  "severity": "CRITICAL",
  "host": "api-internal.example.com",
  "url": "https://api-internal.example.com/helloworld",
  "matcher_name": "spring-core-rce",
  "curl_poc": "curl -X POST -i 'https://api-internal.example.com/helloworld' -H 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di' -H 'X-Bug-Bounty: hacker_username'",
  "evidence": {
    "response_status": 200,
    "matched_string": "class.module.classLoader"
  },
  "first_seen": "2026-09-26T01:50:00Z"
}
```

---

## 6. CLI Command Specification

### Zero-Config Scanning & Advanced Flags
```bash
# Zero-config execution: auto-normalizes input, selects safe profile, caches results
astrarecon scan example.com

# Explicit execution profiles (safe, default, beast)
astrarecon scan example.com --profile safe

# Continuous Delta Scan: active scanners run strictly on new attack surfaces
astrarecon scan example.com --diff-only

# Multi-target scan from a scope file
astrarecon scan --file scope.txt

# Egress routing through Burp Suite with bug bounty identification header
astrarecon scan example.com --proxy "http://127.0.0.1:8080" --header "X-Bug-Bounty: my_handle"
```

### System Doctor & Automated Binary Bootstrap
```bash
# Check status of system dependencies and installed tools
astrarecon doctor

# Automatically download and install missing tools to ~/.astrarecon/bin/
astrarecon doctor --install-missing

# Interactive walkthrough to configure free API keys (Chaos, SecurityTrails, Shodan)
astrarecon keys configure
```

### Session & Cache Management
```bash
# List all past sessions and statuses
astrarecon sessions list

# Inspect session checkpoints and graph execution state
astrarecon sessions inspect 2026-09-26-001-example_com

# Resume an interrupted session
astrarecon scan example.com --resume 2026-09-26-001-example_com

# Compare two past sessions to inspect historical attack surface growth
astrarecon diff 2026-09-20-001 2026-09-26-001

# View CAS storage metrics and purge stale blobs
astrarecon cache stats
astrarecon cache prune --older-than 24h
```

---

## 7. CLI UX Design System Specification

AstraRecon enforces a strict, minimal developer aesthetic inspired by `gh`, `uv`, and `pnpm`.

### Color System Tokens

| Token | Hex Value | Purpose |
| :--- | :--- | :--- |
| `COLOR_BG` | `#000000` | Pure Black viewport background |
| `COLOR_PRIMARY` | `#F8FAFC` | Primary text, titles, and active entity names |
| `COLOR_SECONDARY` | `#94A3B8` | Field labels, timers, and inactive descriptions |
| `COLOR_ACCENT` | `#1DA1FF` | Electric blue single accent for highlights & branding |
| `COLOR_DIVIDER` | `#1E293B` | Subtle panel borders and section separators |
| `COLOR_SUCCESS` | `#22C55E` | Successful completion checkmarks and pass states |
| `COLOR_WARNING` | `#F59E0B` | Retrying nodes and warnings |
| `COLOR_ERROR` | `#EF4444` | Failure indicators and error alerts |

### Live DAG Status Icon Contract

| State | Glyph | Color Token | Semantic Definition |
| :--- | :---: | :--- | :--- |
| `RUNNING` | `▶` | `COLOR_ACCENT` | Node worker is currently executing |
| `WAITING` | `●` | `COLOR_SECONDARY` | Upstream dependencies have not yet completed |
| `SUCCESS` | `✔` | `COLOR_SUCCESS` | Node exited 0 and produced valid artifacts |
| `RETRY` | `↻` | `COLOR_WARNING` | Node encountered transient error; retry in flight |
| `FAILED` | `✖` | `COLOR_ERROR` | Node exhausted retries or failed unrecoverably |
| `CACHED` | `◈` | `COLOR_ACCENT` | Artifact restored directly from CAS blob store |
| `SKIPPED` | `○` | `COLOR_SECONDARY` | Node bypassed due to upstream branch failure |

---

## 8. Custom Script & Shell Plugin Specification (`subenum.sh`)

Any standalone bash script, shell wrapper, or Python tool can be mounted into AstraRecon as a native DAG node.

### Custom Script Manifest Schema (`plugin.yaml`)
```yaml
schema_version: 1
id: subenum
name: SubEnum Script
stage: subdomains
description: "Custom bash script for multi-source subdomain enumeration"

binary:
  name: bash

inputs:
  - name: target
    type: TargetDomain
    required: true
    source: param

outputs:
  - name: subdomains
    type: FQDN
    format: text_lines
    filename: subdomains.txt

execution:
  command: bash
  args:
    - "/opt/scripts/subenum.sh"
    - "{inputs.target}"
    - "{outputs.subdomains}"
  timeout_seconds: 900
  retry_count: 1

cache:
  policy: fresh
  default_ttl_hours: 24
```

### Script Execution Contracts
1. **Process Isolation:** The script is launched in an isolated POSIX process group (`os.setsid`) to guarantee that child processes are completely terminated on interrupt or timeout.
2. **Artifact Streaming:** Outputs written to `{outputs.<name>}` are atomically ingested into the session directory and hashed into the CAS store.
3. **Exit Code:** Exit code `0` indicates success; non-zero triggers retry or marks dependent nodes as `SKIPPED`.
