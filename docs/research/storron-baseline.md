# Storron baseline — how the reference does it, and how we improve + combine

> **Standing principle.** Every research item and design decision must pass the
> **storron lens**: (1) *how does storron do this today?* (2) *what's worth
> keeping vs improving?* (3) *how do we combine the good parts with our new
> idea?* This is a **living document** — revisit it on every subsystem we touch,
> not once. storron stays read-only reference at
> `/Users/macbookpro/projects/hackatron/storron`.

Columns: **Baseline** = storron today · **Improve** = the gap/opportunity ·
**Combine** = the Aegis approach that keeps the good and folds in our idea.

| Subsystem | Baseline (storron) | Improve | Combine (Aegis) |
|---|---|---|---|
| **Agent execution** | Claude Agent SDK session per agent; `bypassPermissions`, full shell, `maxTurns: 10_000`; watchdog kills runaway bash children | Tools invokable but undocumented to the model; no boundary guardrails | Keep the executor as-is; add **per-tool skills** + **boundary guardrails** (scope/rate/redaction) |
| **Prompt system** | `@include(...)` + variable interpolation; pre-recon dispatches clearnet/onion templates | Onion variant is dead weight; prompts don't reference tools | Reuse `@include`/interpolation; **drop onion**; add a `<tool_skills>` section per category |
| **Pipeline** | 5 phases, Temporal-orchestrated; 5 parallel vuln + 5 parallel exploit agents | Sound — keep | Keep verbatim; map the confirmed toolkit + skills onto each layer |
| **Tooling in image** | nmap, subfinder, whatweb, schemathesis preinstalled; **`playwright-cli` skill** as precedent | Tiny toolkit; only one skill | **Generalize the playwright-cli skill precedent** to the full per-category toolkit |
| **Structured output** | `JsonSchemaOutputFormat`; injection analysis emits `*_exploitation_queue.json` from final structured response | Used for queues, not findings | **Extend the same mechanism** to full **finding records** w/ safe PoC (XBOW pattern) |
| **Findings storage** | Markdown deliverables + Temporal event log | No queryable history or diffs | Add a **datastore**; deliverables become a view over structured findings → **scan-to-scan diffs** |
| **Durability / scheduling** | Temporal workflow per scan; ephemeral `docker run --rm`; per-invocation task queue; clean resume | Strong foundation — keep | Reuse for **scheduled re-scans** as first-class, diffable runs |
| **Egress** | Tor/onion + torsocks + Playwright-over-Tor | Removing simplifies a large surface | **Direct clearnet**; optional normal HTTP proxy that also enforces scope/rate |
| **Providers / models** | DeepSeek default; Anthropic/Bedrock/Vertex/OpenRouter via LiteLLM router | Default isn't the strongest model | Default to **latest Claude** (Opus/Sonnet) for the agents; keep router optional |
| **Dashboard** | `apps/web`: Runs, Findings, Blocked, Attack Surface, History (Gantt), Pending, Settings | No Targets / repo / diff views | **Reuse UI**; add **Targets** (site+repo+schedule) and **diff** views |
| **CLI** | npx Docker orchestrator (`start/logs/status/stop/build`) | Heavy for single-tenant | Dashboard is primary; keep a thin CLI |
| **Output schema** | Findings (ranked vulns) + attack-surface scenarios/kill-chains; strict JSON schema in `attack-surface.txt` + `findings/types.ts` | Keep exactly — dashboard depends on it | **Replicate verbatim** (see `output-schema.md`) |
| **Claude Code prompt** | `scenario.claude_code_prompt` = attack/reproduce prompt at the live target | Companies want a *fix*, not an attack | **Invert to a remediation prompt** targeting the connected repo (file:line + missing_defense) |
| **Auth to target** | login-instructions prompt include + Playwright sessions + `generate-totp` | Keep | Reuse; feed per-Target auth config from the dashboard |
| **Codebase ingest** | `cloneRepo` shallow-clones git URL / zip into `REPOS_DIR/<name>_<ts>`; ephemeral, no versioning or project | No persistent project, no codebase/scan history | **Project model** (`project-model.md`): reuse the ingest as a step that mints an immutable **CodebaseVersion** under a named **Project**; retain versions + scans; artifacts → per-tenant GCS |

## How to apply the lens (process)

1. Before designing any Aegis subsystem, **open the storron source** for it
   (port-target paths are listed in `../architecture.md` §7) and record the
   baseline row above if not already captured.
2. Decide **keep / improve / replace**, with the reason.
3. Only then write the Aegis design — explicitly noting what was carried over.
4. Update this table + an ADR in `../decisions.md`.

## Subsystems still to walk with the lens

- Error handling / retry classification (`services/error-handling/*`).
- Queue validation + deliverable validation (`services/queue-validation/*`).
- Git checkpoint/rollback per scan (`services/git-manager/*`).
- Audit/metrics logging (`audit/*`) → maps well onto our findings datastore.
- Config schema + per-agent distribution (`config-parser/*`).
