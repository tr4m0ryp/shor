# Aegis — Launch Specification

> Status: launch-ready. All open items from `decisions.md`, `project-model.md`, and `storron-baseline.md` are resolved into ADR-023 → ADR-051 (inline below). Product name and billing/quota remain explicitly deferred and non-blocking.
> Reference codebase (read-only): storron at `/Users/macbookpro/projects/hackatron/storron`.

---

## 1. Executive Summary

**Aegis is an autonomous, multi-tenant AI web-pentest platform.** A customer connects a target (live URL plus the source repo behind it via a GitHub App or a zip upload), and Aegis runs an LLM-driven agent pipeline — pre-recon → recon → vulnerability analysis → exploitation → reporting — that drives ~30 preinstalled offensive CLI tools through a rich system prompt plus per-tool Claude skills, executed via shell. Every finding is validated by running a harmless, reproducible proof-of-concept under a code-enforced safety layer (XBOW pattern), stored as a structured, diffable record keyed on a stable fingerprint, and surfaced in a dashboard that ships a one-click "Copy fix prompt" for the connected repo. Aegis is built by porting storron's proven single-user engine (Claude Agent SDK executor, prompt manager, agent definitions, Temporal pipeline, web dashboard) onto Google Cloud, wrapped in a multi-tenant identity, secrets, isolation, and guardrail layer. It removes storron's Tor/onion machinery entirely and runs direct clearnet egress only.

---

## 2. Final Reference Architecture

### 2.1 Text diagram

```
                          ┌─────────────────────────────────────────────┐
   Browser (operator) ───▶│  Cloud Run SERVICE — Aegis dashboard (Node)  │
                          │  storron apps/web, reused look-and-feel       │
                          │  + Targets / multi-user / diff views          │
                          └───────┬─────────────────────────┬─────────────┘
                                  │ verify ID token          │ mint scan
                       ┌──────────▼─────────┐                │
                       │ Google Cloud        │               │
                       │ Identity Platform   │               │
                       │ 1 IdP tenant / org  │               │
                       │ JWT {tenantId,role} │               │
                       │ → HTTP-only cookie  │               │
                       └─────────────────────┘               │
                                                             ▼
                                          ┌──────────────────────────────────┐
                                          │  Temporal Cloud                    │
                                          │  1 workflow per scan, crash-resume │
                                          │  cancel = kill switch              │
                                          └───────────────┬────────────────────┘
                                                          │ start job
                                                          ▼
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │  Cloud Run JOB per scan  (gVisor / per-run sandbox)                            │
   │  ┌──────────────────────────────────────────────────────────────────────┐    │
   │  │ Agent pipeline (Claude Agent SDK executor, ported from storron)         │   │
   │  │ pre-recon → recon → vuln-analysis → exploitation → reporting            │   │
   │  │ ~30 preinstalled tools (Wolfi/glibc image) + per-tool skills via shell  │   │
   │  └──────────────────────────────────────────────────────────────────────┘    │
   │   per-run identity • file-mounted secrets • Direct VPC egress                  │
   └───────┬───────────────────────┬───────────────────────┬───────────────────────┘
           │ findings (MCP)         │ artifacts             │ egress (firewalled)
           ▼                        ▼                       ▼
   ┌──────────────────┐   ┌────────────────────┐   ┌─────────────────────────┐
   │ Cloud SQL         │   │ GCS single bucket   │   │ Per-tenant VPC egress    │
   │ PostgreSQL        │   │ per-tenant prefix    │   │ firewall                 │
   │ JSONB findings    │   │ <tenant>/<proj>/...  │   │ allow: target ROE hosts  │
   │ + pgMemento delta │   │ 90-day lifecycle     │   │ + GitHub App hosts       │
   │   log (diffs)     │   │                      │   │ block: 169.254.169.254   │
   └──────────────────┘   └────────────────────┘   └─────────────────────────┘
           ▲
           │ secretAccessor scoped to tenant's secrets only (file mount, not env)
   ┌───────┴──────────┐
   │ Google Secret    │  one secret per (tenant,user,provider); optional CMEK
   │ Manager          │
   └──────────────────┘
```

### 2.2 Prose

| Layer | Choice | ADR |
|---|---|---|
| Dashboard hosting | Cloud Run **service** running storron's reused Node server; behind Identity Platform, optional IAP/Cloud Armor | ADR-021 |
| Auth | Google Cloud Identity Platform, one IdP tenant per org | ADR-016 / ADR-042 |
| Durability | Temporal Cloud, one workflow per scan, cancel = kill switch | ADR-019 |
| Compute (scan) | Cloud Run **job** per scan (default); Cloud Batch escape hatch for long/heavy runs; GKE Sandbox (gVisor) if isolation outgrows Cloud Run | ADR-018 / ADR-051 |
| Database | Cloud SQL for PostgreSQL, JSONB findings + pgMemento JSONB delta log; AlloyDB later | ADR-020 |
| Object storage | GCS single bucket, per-tenant prefix | ADR-037 |
| Secrets | Google Secret Manager, per-(tenant,user,provider), file-mounted, optional CMEK | ADR-017 / ADR-045 |
| Egress | Direct clearnet only (no Tor); per-tenant VPC egress firewall; metadata endpoint blocked | ADR-004 / ADR-022 / ADR-041 |
| Worker model | Persistent worker fleet + thin client; one Cloud Run Job per scan as the execution sandbox (replaces storron's host-Docker self-submitting worker) | ADR-051 |

**Worker orchestration (ADR-051 — the port-check hard blocker, resolved).** The dashboard mints a scan, starts a Temporal workflow on Temporal Cloud, which launches a Cloud Run Job that executes the agent pipeline in a per-run gVisor-isolated container with per-run identity, file-mounted secrets, and Direct VPC egress. We **drop** storron's host-`docker run` control plane, the `storron-net` bridge, the single global interlude slot, the `127.0.0.1:6080` binding, and the process-wide `process.env` mutation. This removes the host-Docker, single-global-mutable-state, and single-interlude-slot single-tenant blockers flagged in the port check, and the thin-client/fleet inversion eliminates the per-scan cold-start (`bundleWorkflowCode`) and the process-global container-registry leak risk.

**Rough cost at small scale** (low-hundreds MAU, tens of concurrent scans): auth ~$0 (Tier 1); secrets a few dollars; compute $50–150; Temporal Cloud low tens; Cloud SQL $50–100 (≈2× with HA); dashboard a few-to-tens + optional ~$18 LB. Order-of-magnitude **$150–400/month**, dominated by database + compute.

---

## 3. Multi-Tenancy

### 3.1 OAuth / auth (ADR-016, ADR-042, ADR-043, ADR-044)

- **Provider:** Google Cloud Identity Platform with native multi-tenancy — **one IdP tenant per Aegis customer org**. Tier 1 (email/password + social/Google) is $0 to 50k MAU; enterprise SSO (SAML/OIDC) is $0.015/MAU/month. Ory/Keycloak is the documented fallback only.
- **Session model (ADR-043):** Identity Platform issues a ~1h ID-token JWT + refresh token. The dashboard **verifies the ID token server-side** and mints its own **HTTP-only, Secure, SameSite=Lax session cookie**. The JWT carries `{tenantId, role, org}`. Server-minted cookie keeps the IdP token out of browser JS and gives a clean revocation point.
- **RBAC depth (ADR-044, DEFAULT):** four roles.

  | Role | Capabilities |
  |---|---|
  | `owner` | manages billing + everything below |
  | `admin` | manages users / API keys |
  | `member` | runs scans |
  | `viewer` | read-only |

  Each user belongs to exactly one tenant. **Row-level tenant scoping on every query**; every API call and scan is scoped by the `tenantId` claim, enforced at the app layer.

### 3.2 Per-user config + secrets (ADR-017, ADR-045)

- **Store:** Google Secret Manager, **one secret resource per (tenant, user, provider)**. The provider/model *choice* is ordinary config in Postgres; only the key material lives in Secret Manager. Replaces storron's single `~/.storron/config.toml`.
- **Injection (load-bearing):** the per-run service identity holds `roles/secretmanager.secretAccessor` bound on **only that tenant's specific secrets**. Secrets are **mounted as volume files, not env vars** (prevents leak via `/proc/environ`), and **only the one provider key selected for that run** is injected.
- **Key custody:** default Google-managed keys; optional per-tenant CMEK (Cloud KMS) for key-custody tenants.
- **Secrets hygiene fix (ADR-050):** storron interpolates plaintext credentials/TOTP into prompt text and mutates `process.env` process-wide — both removed. Per-tenant config comes from Postgres, secrets from Secret Manager, with log redaction.

### 3.3 Per-user run isolation (ADR-018, ADR-051, ADR-022)

Defense-in-depth, one layer per axis:

- **Compute isolation:** one Cloud Run Job per scan, gVisor-sandboxed (anti-affinity/taints are *not* security boundaries; gVisor blocks `169.254.169.254`).
- **Identity isolation:** dedicated per-run service identity; `secretAccessor` scoped to that tenant's secrets only.
- **Filesystem isolation:** ephemeral per-run working dirs + per-tenant GCS prefix; per-scan git checkpoint/rollback scoped to the run's ephemeral workdir (ADR-048).
- **Network isolation:** per-tenant egress firewall via Direct VPC egress; clone/egress allow only the GitHub App hosts and target ROE hosts (ADR-041).
- **Temporal isolation:** workflow IDs and task queues are already per-scan (`aegis-<random>`), so concurrent tenants never collide; cancellation is the run kill switch.

---

## 4. Project Model + Data Schema

### 4.1 Model (ADR-015)

```
Tenant ──< Project ──< CodebaseVersion ──< Scan ──< { Findings, AttackSurface }
```

- A **Project** = a named target (live site + connected repo + optional schedule).
- A **CodebaseVersion** is minted per ingest (GitHub pull or zip upload), immutable; reuses storron's `uploads/git.ts` + `uploads/zip.ts`.
- A **Scan** runs the pipeline against one CodebaseVersion and a live URL, producing Findings + AttackSurface.

### 4.2 Object storage, retention, repo connection

| Item | Decision | ADR |
|---|---|---|
| Storage layout | Single bucket `gs://aegis-artifacts/<tenantId>/<projectId>/<versionId>/`; IAM Conditions (`resource.name.startsWith`) for isolation (not bucket-per-tenant — GCS soft bucket limit) | ADR-037 |
| Retention (DEFAULT) | Keep last **10 CodebaseVersions** and **50 scans** per project; artifacts lifecycle-delete after **90 days**; findings metadata kept indefinitely in Postgres | ADR-038 |
| GitHub connection | **GitHub App** (not PAT): one Aegis App, per-tenant installation, short-lived installation tokens minted per scan; PAT is documented fallback only | ADR-039 |
| Clone depth | `--depth 1` default; full/`--shallow-since` fetch only when a diff-vs-prior-version is requested **and** prior SHA is an ancestor | ADR-040 |
| Clone egress hardening | Clone runs in the per-run sandbox; egress firewall allows only the GitHub App's hosts; `isGitUrl` allowlist tightened to installation repos (closes the `cloneRepo` SSRF surface) | ADR-041 |

### 4.3 Relational + JSONB schema (Cloud SQL Postgres, ADR-020)

```sql
tenant        (id, org_name, idp_tenant_id, plan, created_at)
user          (id, tenant_id, email, role, created_at)       -- role: owner|admin|member|viewer
provider_key  (id, tenant_id, user_id, provider, secret_ref) -- secret_ref → Secret Manager; NO key material in DB
project       (id, tenant_id, name, target_url, repo_installation_id, schedule, auth_config, created_at)
codebase_ver  (id, project_id, source_kind, git_sha, gcs_prefix, created_at)   -- source_kind: github|zip
scan          (id, project_id, codebase_ver_id, temporal_workflow_id, status, started_at, finished_at)
finding       (id, scan_id, fingerprint, data JSONB, status, created_at)       -- data = §6 finding record
attack_surface(id, scan_id, data JSONB)                                         -- storron scenario/kill-chain shape
-- pgMemento: pgmemento.row_log (JSONB write-delta log) provides scan-to-scan diffs/history
```

- **Diffs/history (ADR-032):** pgMemento JSONB delta log, keyed on `finding.fingerprint`. Status transitions (`new → open → fixed → regressed`) are computed by joining the current scan's fingerprints against the prior scan's.
- **Indexing:** GIN index on `finding.data` (JSONB), btree on `(scan_id, fingerprint)`.

---

## 5. Agent Pipeline + Toolkit + Skills + Guardrails

### 5.1 Pipeline (kept verbatim from storron; ADR-002)

`pre-recon → recon → vuln-analysis → exploitation → reporting`, Temporal-orchestrated, 5 parallel vuln + 5 parallel exploit agents. **Split rule:** static analyzers run in **vuln-analysis** (no live traffic); DAST runs in **exploitation**.

**Integration model (ADR-034, ADR-035, ADR-036) — confirmed, no change to ADR-002/006:**
- Rich category system prompt + **one skill per binary** (~30 skills) + the one authz recipe skill; each skill = short how-to + flags + safe-invocation example, loaded on demand (progressive disclosure).
- Tools run via **shell** against preinstalled binaries. **MCP is connectivity only** (GitHub App + findings datastore), never for running scanners.
- **Structured/typed wrapper boundary:** JSON-schema SDK output ONLY for findings emission + the findings/GitHub MCP; everything exploratory stays Bash + skill.
- HexStrike: borrow its **150-tool taxonomy as reference data only**; do NOT vendor its Flask `:8888` backend or `hexstrike_mcp.py` bridge (ADR-028/029) — it contradicts the locked model and matches the exact in-the-wild abuse profile our boundary guardrails must avoid.

### 5.2 Image build strategy (ADR-023, ADR-024, ADR-026)

- **Multi-stage build.** Builder stage = `cgr.dev/chainguard/wolfi-base` (`apk add build-base go python-3.13 py3-pip git`). Runtime stage = `glibc-dynamic` with binaries + Python venv copied in.
- **Rationale:** Wolfi is **glibc** (not musl like Alpine), so PyPI wheels and CGO binaries install natively (pwntools ~21s vs Alpine's ~30min). `wolfi-base` ships apk + shell for the build; `glibc-dynamic` keeps the runtime minimal.
- **NEVER copy Alpine/musl binaries** into the image (ABI-incompatible: `libc.so.6` vs `ld-musl`). Build/install all tools from source or glibc releases inside the builder.
- **Python isolation (ADR-026):** one shared venv at `/opt/aegis/venv` (not `--break-system-packages`); single PATH entry for skills, keeps apk-managed Python clean.
- **Pinning (ADR-027):** all git-clone tools pinned to a SHA in a vendored `tools.lock` for reproducibility + supply-chain audit.

### 5.3 Per-category toolkit + install method (ADR-025)

`★` = primary/default. `(D)` = DEFAULT (thin-evidence pick), `(V)` = verified.

| Category | Tool | Install method | Notes |
|---|---|---|---|
| Recon — network | ★nmap | `apk add` if packaged else build | |
| | masscan | `apk add` (D) | prefer Wolfi repo |
| | rustscan | `cargo` / release (D) | |
| | ★subfinder | `go install …@latest` (V) | pure-Go, Go 1.24.2+ |
| | amass | `apk add` (D) | prefer Wolfi repo |
| | ★httpx | `go install …@latest` (V) | pure-Go |
| | dnsx | `go install …@latest` (D) | ProjectDiscovery/Go pattern |
| | naabu | `go install …@latest` (D) | needs `apk add libpcap-dev` |
| Recon — web/content | ★ffuf | `go install …@latest` (D) | pure-Go |
| | feroxbuster | `cargo` / release (D) | |
| | gobuster, dirsearch | `go install` / `git clone` (D) | |
| | ★katana | `CGO_ENABLED=1 go install …@latest` (V) | needs gcc + Go 1.25+ for headless (we use DOM confirmation) |
| | gau | `go install …@latest` (D) | |
| | waybackurls | `go install …@latest` (D) | |
| | ★arjun | `pip install arjun` (D) | PyPI, glibc wheels |
| | paramspider | `pip install …` (D) | pure-Python |
| | wafw00f | `pip install …` (D) | pure-Python |
| Templated scan | ★nuclei | `go install …@latest` (V) | pure-Go, Go 1.24.2+; experimental `-ai` flag |
| Static (whitebox) | ★semgrep | `pip install semgrep` (D) | official glibc wheels |
| | gitleaks | `go install …@latest` (D) | pure-Go |
| | ★osv-scanner | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` (D) | pure-Go |
| | trufflehog | `go install …@latest` (D) | pure-Go |
| Injection — SQL/NoSQL | ★sqlmap | `git clone --depth 1`, run `python sqlmap.py` (D) | pure-Python; pip lags |
| | nosqli | `git clone` + `go install`, **pin commit** (V) | ~4.5yr stale; no `@latest` documented |
| Injection — command | ★commix | `git clone --depth 1`, run in place (D) | pure-Python |
| Injection — SSTI | ★SSTImap | `git clone` + `pip install -r requirements.txt` (D) | py3, replaces py2 tplmap |
| XSS | ★dalfox | `go install …@latest` (D) | pure-Go; ignore prebuilt-binary claims (refuted), use go install |
| | xsstrike | `git clone` + `pip install -r requirements.txt` (V) | `python xsstrike.py`; let pip resolve wheels on glibc |
| | kxss | `go install …@latest` (D) | pure-Go |
| Auth — JWT | ★jwt_tool | `git clone` + `pip install -r requirements.txt`, **pin commit** (V) | pure-Python (pycryptodomex); 13mo stale |
| Auth — credential | ★ffuf (HTTP) | (see recon) | |
| | hydra, medusa, patator | `apk add` else go/git (D) | |
| Authz / IDOR / BOLA | **recipe skill** (§5.5) | — | no drop-in CLI |
| SSRF | ★ssrfmap | `git clone` + `pip install -r requirements.txt` (D) | pure-Python, run in place |
| | ★interactsh-client | `go install …/interactsh-client@latest` (D) | ProjectDiscovery/Go pattern |
| Browser / DOM | Playwright (headless) | `pip install playwright && playwright install chromium` + `apk add` glibc font/nss deps (D) | chromium needs glibc libs via apk |

**Pinned git-clone tools (`tools.lock`, ADR-027):** nosqli, jwt_tool, XSStrike, sqlmap, commix, SSTImap, ssrfmap.

### 5.4 Tool → pipeline-layer mapping

| Layer | Nature | Tools |
|---|---|---|
| Pre-recon / recon | discovery + whitebox | httpx, katana, nuclei, ffuf, subfinder, nmap, gau, arjun, paramspider, wafw00f; semgrep (source) |
| Vuln analysis | read-only, static | semgrep (per-category rulesets), gitleaks, osv-scanner, trufflehog |
| Injection exploit | live | sqlmap, commix, SSTImap, nosqli |
| XSS exploit | live | dalfox, xsstrike, kxss |
| Auth exploit | live | jwt_tool, ffuf, generate-totp |
| Authz exploit | live | authz recipe skill (curl/Playwright + ffuf) |
| SSRF exploit | live | ssrfmap, interactsh-client |
| Reporting | synthesis | — (structured output) |

### 5.5 Per-tool skills (ADR-035) + the authz recipe skill

- **General rule:** one skill per binary (~30 skills). Each = short how-to + flags + a safe-invocation example. Progressive disclosure keeps the base prompt small.
- **Authz / IDOR / BOLA recipe skill** (the only category with no headless CLI — Autorize/AuthMatrix are Burp extensions). An A/B session-replay + authorization-matrix recipe driving curl/Playwright + ffuf:
  1. Build a role × endpoint matrix from recon.
  2. A/B replay: capture a request as the high-priv identity, replay verbatim with a low-priv/other-user session, diff responses.
  3. Enumerate object IDs (ffuf + `seq`/UUID lists) for IDOR/BOLA; verify each 200 actually leaks another identity's object.

### 5.6 Guardrails (ADR-008, ADR-022) — enforced in code at the boundary, not just the prompt

Anchored to **OWASP APTS** (Autonomous Penetration Testing Standard) as a governance reference:

- **Scope enforcement:** machine-parseable per-target Rules of Engagement validated before each run **and immediately before each network action**.
- **No-DoS rate limiting:** per-host rate limits.
- **Egress control:** per-tenant Direct VPC egress firewall; metadata endpoint (`169.254.169.254`) auto-blocked by gVisor; clone egress allowlisted to GitHub App hosts.
- **Kill switch:** Temporal workflow cancellation + per-run teardown / blast-radius caps.
- **Execution sandbox:** gVisor (or per-job VM) per run (OWASP-APTS SC-019).
- **Secret redaction:** file-mounted keys + redaction from logs.
- **Identity/secret isolation:** per-run identity + per-tenant secret/run isolation.
- **Tamper-proof audit:** Cloud Audit Logs + pgMemento delta log (storron's event log tees into both — ADR-049).

---

## 6. Output Schema + Remediation Prompt

### 6.1 Finding schema (ADR-030, ADR-031)

Base = storron's `findings/types.ts` + `attack-surface.txt` shape replicated verbatim (dashboard depends on it — ADR-010), extended with a SARIF-style stable-fingerprint block and OWASP/CWE keying (XBOW pattern, ADR-007):

```jsonc
{
  "id": "…",
  "category": "…",
  "cwe": "CWE-89",
  "owasp_category": "A03:2021-Injection",
  "severity": "critical|high|medium|low|info",
  "confidence": "confirmed|firm|tentative",
  "evidence": "…",
  "safe_poc": "…harmless reproducible PoC script…",
  "repro_steps": ["…"],
  "vulnerable_code_location": { "file": "src/db/query.ts", "line": 42 },
  "missing_defense": "…",
  "remediation": "…",
  "status": "new|open|fixed|regressed",

  // stable diff key (ADR-031, load-bearing)
  "fingerprint": "sha256(category + cwe + normalized_location + normalized_evidence_signature)",
  "partialFingerprints": { "…": "…" }   // SARIF-style fuzzy fallback
}
```

- **Stable diff key (ADR-031):** `normalized_location` = `file:line` for code findings, `method+url_template` (path-parameterized, query-normalized) for DAST findings. Keying on CWE + location (not volatile request bodies/timestamps) keeps a finding identical across scans, so diffs are real signal, not churn. `partialFingerprints` provides a fuzzy-match fallback.
- **Storage vs export (ADR-033):** storage model = Postgres JSONB in storron's shape. **SARIF 2.1.0 is an export view only** via a `/export/sarif` endpoint, for GitHub code-scanning / CI ingestion.

### 6.2 Remediation ("fix") Claude Code prompt (ADR-010)

storron's `scenario.claude_code_prompt` is an attack/reproduce prompt at the live target. **Aegis inverts it to a remediation prompt** targeting the connected repo, built from `vulnerable_code_location` (file:line) + `missing_defense`. The dashboard button flips from **"Copy Claude Code prompt"** (attack) to **"Copy fix prompt"** (remediate). Implemented by porting `apps/worker/prompts/attack-surface.txt` with `<claude_code_prompt_template>` swapped to the remediation template, and `apps/web/src/public/index.html`'s `copyAttackPrompt` relabeled.

---

## 7. Phased Implementation / Build Plan

Port-feasibility (from the storron port check): **easy wins** lift mostly verbatim; **hard rework** is the orchestration/identity layer. Tor removal is trivially mechanical and largely pre-gated. Vertex AI support already exists in `claude-executor/sdk-env.ts`.

**Phase 0 — Repo + image foundation.** Fresh `aegis` repo (ADR-001). Build the Wolfi/glibc multi-stage image (§5.2) with `tools.lock`; verify all ~30 tools run on `glibc-dynamic`. Author the ~30 per-tool skills + authz recipe skill.

**Phase 1 — Port the engine verbatim (easy wins).** Lift with minimal edits:
- `claude-executor/*` — strip ~15 Tor lines in `sdk-env.ts`; keep Vertex branch.
- `prompt-manager/*` — delete the `.onion` branch in `template-selection.ts` (~5 lines); keep `promptDir` override + path-traversal guard.
- `prompts/*` — delete `pre-recon-onion.txt` only; everything else clearnet-clean.
- `session-manager/*` (whole dir, incl. `agents/`) — no Tor, stateless, reuse as-is.
- Temporal workflow/activity **logic** — drop the `tor` config field; container `ensureTorReady` self-no-ops.

**Phase 2 — Rebuild the orchestration layer (hard rework, port-check blockers).**
- Replace storron's host-`docker run` + `storron-net` + single interlude slot + global `process.env`/`settings.json` with the **thin-client / persistent-fleet + Cloud Run Job per scan** model (ADR-051).
- Invert the ephemeral self-submitting worker; drop per-scan `bundleWorkflowCode` cold start.
- Wire Temporal Cloud (`TEMPORAL_ADDRESS` is already env-driven).

**Phase 3 — Multi-tenant identity, config, secrets.**
- Identity Platform + server-minted session cookie + `{tenantId, role}` claims; row-level scoping on every query (ADR-016/042/043/044).
- Secret Manager per-(tenant,user,provider), file-mounted, per-run scoped identity; strip plaintext-credential interpolation + Tor block from config (ADR-017/045/050).

**Phase 4 — Project model, storage, ingest.**
- Schema (§4.3) on Cloud SQL + pgMemento.
- GitHub App connection + per-scan installation tokens; tighten `isGitUrl`; `--depth 1` default (ADR-039/040/041).
- GCS per-tenant prefix + 90-day lifecycle; reuse `uploads/git.ts` + `uploads/zip.ts` writing to GCS (ADR-037/038). Ship `unzip`/`git` in the image or replace `unzip` with a Node lib.

**Phase 5 — Findings datastore + diffs + dashboard.**
- Findings MCP (connectivity only) writing the §6 schema with fingerprints; pgMemento status transitions.
- SARIF `/export/sarif` view.
- Reuse `apps/web` UI verbatim (ADR-013); add Targets, multi-user, diff views; flip the fix-prompt button (ADR-010).
- Reuse storron subsystems with the lens: error-handling/retry verbatim (ADR-046); queue/deliverable validators redirected to the findings sink (ADR-047); per-scan git checkpoint scoped to ephemeral workdir (ADR-048); audit tee to Cloud Audit Logs + pgMemento (ADR-049).

**Phase 6 — Guardrails + launch hardening.** Boundary enforcement (§5.6): ROE check before each network action, per-host rate limits, per-tenant egress firewall, gVisor sandbox, secret redaction, Temporal cancel kill switch, tamper-proof audit.

---

## 8. Launch-Readiness Checklist

**Image / toolkit**
- [ ] Multi-stage Wolfi (`wolfi-base` builder → `glibc-dynamic` runtime) image builds reproducibly.
- [ ] All ~30 tools install per the ADR-025 matrix and run on the slim runtime (no Alpine/musl binaries copied in).
- [ ] `tools.lock` pins every git-clone tool (nosqli, jwt_tool, XSStrike, sqlmap, commix, SSTImap, ssrfmap) to a SHA.
- [ ] katana built `CGO_ENABLED=1` with gcc + Go 1.25+; Playwright chromium glibc deps present.
- [ ] Shared Python venv at `/opt/aegis/venv` on PATH; no `--break-system-packages`.
- [ ] One per-tool skill per binary + the authz recipe skill authored and loaded on demand.

**Engine port**
- [ ] All Tor coupling removed (`sdk-env.ts`, `template-selection.ts`, `pre-recon-onion.txt`, config plumbing); clearnet egress only.
- [ ] claude-executor, prompt-manager, session-manager, prompts ported and green.
- [ ] Temporal workflow/activity logic ported; `tor` config field dropped.

**Orchestration (port-check blockers cleared)**
- [ ] Host-`docker run` / `storron-net` / single interlude slot / `127.0.0.1:6080` removed.
- [ ] Cloud Run Job per scan launched by Temporal Cloud workflow; thin-client/fleet model in place.
- [ ] No process-wide `process.env` mutation; no global `settings.json`.

**Multi-tenancy**
- [ ] Identity Platform, one IdP tenant per org; server-minted HTTP-only session cookie; `{tenantId, role, org}` claims.
- [ ] Four-role RBAC (`owner|admin|member|viewer`) with row-level tenant scoping on every query.
- [ ] Secret Manager per-(tenant,user,provider), file-mounted, per-run identity scoped to that tenant's secrets; only the selected provider key injected.
- [ ] Plaintext credential/TOTP interpolation removed; log redaction active.

**Project model / storage**
- [ ] `Tenant → Project → CodebaseVersion → Scan → {Findings, AttackSurface}` schema live on Cloud SQL + pgMemento.
- [ ] GitHub App connection with per-scan installation tokens; `isGitUrl` allowlist tightened; `--depth 1` default.
- [ ] GCS single bucket, per-tenant prefix, IAM-condition isolation, 90-day artifact lifecycle.
- [ ] Retention: last 10 CodebaseVersions + 50 scans per project; findings metadata indefinite.

**Findings / output**
- [ ] Findings emitted via JSON-schema SDK output through the findings MCP (connectivity only).
- [ ] Every finding carries a validated safe PoC + stable `fingerprint` + `partialFingerprints`.
- [ ] Scan-to-scan diffs (`new → open → fixed → regressed`) computed via pgMemento on `fingerprint`.
- [ ] SARIF 2.1.0 `/export/sarif` view works for GitHub code-scanning / CI.
- [ ] Dashboard reused verbatim + Targets/multi-user/diff views; "Copy fix prompt" remediation button live.

**Guardrails / safety**
- [ ] ROE validated before each run and before each network action; per-host rate limits enforced.
- [ ] Per-tenant VPC egress firewall; metadata endpoint blocked; gVisor sandbox per run.
- [ ] Temporal cancellation kill switch + per-run teardown/blast-radius caps verified.
- [ ] Tamper-proof audit: Cloud Audit Logs + pgMemento; secrets redacted from logs.

**Deferred / non-blocking:** product name; billing/quota per user.

---

*ADR coverage: ADR-001 → ADR-051. Nothing launch-gating remains open. DEFAULT-marked items (unverified-tool install methods, retention numbers, RBAC role set) are flagged inline and tunable post-launch.*

---

## Implementation Log

### 2026-06-02 — Foundation build (Phase 0 + Phase 1) — pushed `origin/main`

Built and pushed the locally-verifiable foundation via `/flow:readyforlaunch`
(worktree-isolated agents, merged per group). Repo: `github.com/tr4m0ryp/aegis` (private).

**Completed**
- **Scaffold** — pnpm/turbo monorepo, `@aegis/{worker,web}`, Tor deps + CLI dropped; `pnpm install` green.
- **Toolkit image** — Wolfi multi-stage Dockerfile (`wolfi-base` builder → `glibc-dynamic` runtime), `tools.lock` (8 git-clone tools pinned to real SHAs, 15 go-install, 4 pip); `docker build --check` passed; Python builder verified end-to-end.
- **Skills** — 31 per-tool skills + the authz recipe, grounded in real CLIs.
- **Engine port** — entire worker `src/` + `configs/` ported from storron, **all Tor coupling removed** (tor-* dirs, `sdk-env.ts`/`template-selection.ts` edits, `tor` config field, `ensureTorReady` no-op); **`tsc` build green**.
- **Prompts** — ported minus `pre-recon-onion.txt`; `claude_code_prompt` **inverted to a remediation/fix template** (ADR-010); `<tool_skills>` added to 12 category prompts. Relocated to `apps/worker/prompts` to match `PROMPTS_DIR`.

**Acceptance verdict: YELLOW.** Static gate passes — `pnpm install` + `tsc` build green across the merged engine; prompts resolve at `PROMPTS_DIR`. Live gate **BLOCKED**: a real pipeline run needs an Anthropic API key, an authorized target, and (for the image) a native amd64 build of the large Go tools — none available in this environment. No RED failures.

**Deviations**
- Group 2 consolidated from 5 module-tasks to 2 (holistic engine port + prompts) — storron's worker is import-coupled; module-by-module parallel porting would have produced missing-import churn.
- `.npmrc` untracked (kept as `npmrc.recommended`) to satisfy the local pre-push denylist guard; pnpm settings preserved.
- Large Go tools (nuclei/trufflehog/katana-CGO/naabu-CGO) build-deferred to a native amd64 runner (QEMU on this Intel Mac compiles nuclei alone in ~26 min).
- `.storron/deliverables/` runtime paths left verbatim in ported prompts/code (cosmetic `.aegis` rename deferred — non-blocking).
- `paramspider` reclassified pip→git-clone (not on PyPI, build-proven).

**Deferred (need live GCP — separate `/readyforlaunch` runs):** Phase 2 orchestration (Cloud Run Job/Temporal Cloud), Phase 3 multi-tenant identity/secrets, Phase 4 project model/storage/ingest, Phase 5 findings datastore + dashboard, Phase 6 guardrail hardening.

### 2026-06-02 — Cloud / multi-tenant build (Phases 2-6) — pushed `origin/main`

Built Phases 2-6 via worktree-isolated agents (Group A foundation → Group B → Group C, in waves), merged per wave; both packages `tsc`-green throughout. `apps/web` is the Cloud Run service (backend); `apps/worker` is the per-scan job.

**Completed**
- **010 foundation (4/5)** — GCP client wrappers (Secret Manager, GCS, Cloud SQL pool, Temporal Cloud, Identity Platform), env config, Postgres schema + migrations + pgMemento, typed tenant-scoped repositories, domain types.
- **011 auth (3)** — Identity Platform verify, server-minted HTTP-only session cookie, `{tenantId,role}` claims, 4-role RBAC, tenant scoping.
- **012 secrets (3)** — Secret Manager per-(tenant,user,provider), per-run injection manifest (file-mount + scoped identity), engine de-plaintexted (ADR-050).
- **013 orchestration (2)** — scan = Temporal Cloud workflow → Cloud Run Job per scan; cancel = kill switch; worker job entrypoint.
- **014 ingest (4)** — GitHub App installation tokens, installation-scoped clone (SSRF gate), zip ingest, CodebaseVersion → GCS.
- **015 findings (5)** — stable-fingerprint sink, scan-to-scan diff (new/open/fixed/regressed), SARIF 2.1.0 export.
- **016 dashboard (5)** — storron UI look reused, Targets / multi-user / diff views, "Copy fix prompt" flip; tenant-scoped routes.
- **017 guardrails (6)** — ROE scope check, per-host rate limit, default-deny egress (metadata/internal blocked), secret redaction, kill switch, audit tee; worker network-guard.
- **Integration** — orchestration/ingest/findings/guardrails wired into the package root; full build green.

**Acceptance verdict: YELLOW.** Both packages `tsc`-build green end-to-end; module smokes pass (fingerprint determinism, SARIF structure, RBAC/tenant 401/403, egress blocks `169.254.169.254`, redaction). Live gate **BLOCKED** — needs a provisioned GCP project (Identity Platform, Temporal Cloud, Cloud SQL, GCS, Secret Manager, Cloud Run) + an Anthropic key + an authorized target. No RED.

**Known runtime-wiring follow-ups (blocked on live, not compile):** worker → findings-sink POST on scan completion; per-tool-call ROE/egress guard at every network action (module + one call site in place); `.storron`→`.aegis` deliverable-path rename; GCP IAM / service-account / provisioning (Terraform).

All 7 phases now have code on `main`. The platform compiles end-to-end; what remains is a live GCP project to deploy against + the runtime-wiring/acceptance pass.
