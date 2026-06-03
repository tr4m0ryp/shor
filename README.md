# Shor: An Autonomous Multi-Tenant AI Pentester for Web Apps and APIs

**Shor** is a hosted platform that turns a large-language-model
agent into a working web-application penetration tester. A customer connects a target —
a **live URL** plus the **source repository** behind it — and Shor runs a staged agent
pipeline that finds, *proves*, and explains vulnerabilities, then hands back a one-click
prompt to fix each one in the connected repo.

> **Defensive and authorized-testing use only.** See [Disclaimer](#disclaimer--responsible-use).

## Project Overview

Manual web pentests are slow, expensive, and stale the moment the code changes. Automated
DAST scanners are fast but noisy — they flag *possible* issues without proving them, drown
teams in false positives, and have no memory of what was already triaged. The gap is a tool
that reasons like a tester (chains recon into exploitation, reads the source to confirm a
finding, writes a working proof-of-concept) **and** behaves like a product (multi-tenant,
re-runnable on every push, diff-aware across scans, safe by construction).

Shor is that tool. It drives roughly **30 preinstalled offensive CLI tools** (sqlmap,
dalfox, nuclei, ffuf, semgrep, and more) through a **rich system prompt plus one loadable
skill per tool**, executed via shell inside an isolated, per-scan sandbox. Each agent works
a single OWASP category; every finding is **validated by running a harmless, reproducible
proof-of-concept** (the *minimum-impact* "XBOW" pattern — stop at the smallest convincing
proof, no data exfiltration, no persistence). Confirmed findings are stored as **structured,
diffable records** keyed on a stable fingerprint, so the dashboard can show what is **new,
still open, fixed, or regressed** between any two scans — and offer a **"Copy fix prompt"**
that turns each attack into a remediation task for the repo.

The engine is a hardened, multi-tenant rebuild of a proven single-user pentest agent, ported
onto **Google Cloud** (Identity Platform, Temporal Cloud, Cloud Run, Cloud SQL, Secret
Manager, GCS) and wrapped in a **code-enforced safety layer** — rules-of-engagement scope
checks, per-host rate limits, a default-deny egress allowlist, secret redaction, and a kill
switch. All Tor/onion machinery from the original engine has been removed; Shor runs **direct
clearnet egress only**.

## Core Architecture / How It Works

Shor splits into two deployable units plus managed cloud services. The **control plane** (a
long-running web service) owns identity, data, secrets, and orchestration; the **data plane**
(one ephemeral job per scan) runs the actual agent pipeline in isolation.

```
   Operator browser
         |  HTTPS (session cookie)
         v
  +-----------------------------------------------+
  |  Cloud Run SERVICE  -  shor-web              |
  |  dashboard UI + control-plane API             |
  |  (serves the static UI; auth, data, secrets,  |
  |   ingest, findings, guardrails, orchestration)|
  +--+----------------+----------------+----------+
     | verify token   | mint scan      | read/write
     v                v                v
 Identity         Temporal Cloud    Cloud SQL (Postgres)
 Platform         1 workflow/scan    JSONB findings +
 1 tenant / org   cancel = kill      pgMemento delta log
                      |               (scan-to-scan diffs)
                      | start job
                      v
  +-----------------------------------------------+
  |  Cloud Run JOB per scan  -  shor-scan-worker |
  |  gVisor sandbox, per-run service identity      |
  |                                               |
  |  Claude Agent SDK pipeline (via shell):        |
  |  pre-recon -> recon -> vuln -> exploit -> report|
  |  ~30 offensive CLI tools + per-tool skills     |
  +--+---------------+----------------+------------+
     | findings      | artifacts      | egress (firewalled)
     v               v                v
  shor-web       GCS bucket       Target ROE hosts
  HTTP sink       per-tenant       + GitHub hosts only
                  prefix           (169.254.169.254 blocked)

  Secret Manager - one secret per (tenant, user, provider),
  file-mounted into the job, scoped to that tenant only.
```

**1. Connect and scan.** A tenant creates a **Project** — a named target = live URL +
connected repo (via the GitHub App or "Connect with GitHub" OAuth) + optional cron schedule
+ target auth/rules-of-engagement config. White-box projects clone the repo; black-box
projects run URL-only.

**2. Mint a run.** Triggering a scan pins an immutable **CodebaseVersion** (a git SHA pulled
to a per-tenant GCS prefix), records a **Scan** row, and starts a **Temporal Cloud workflow** —
one workflow per scan, crash-resumable, where cancellation *is* the kill switch.

**3. Execute in isolation.** The workflow launches a **Cloud Run Job** for that scan only:
gVisor-sandboxed, with a per-run service identity whose secret access is scoped to that one
tenant, the selected provider key **mounted as a file** (never an env var), and a per-tenant
VPC egress firewall that allows only the target's in-scope hosts and GitHub. The job
materializes the repo snapshot and runs the pipeline **in-process**.

**4. The agent <-> tool model.** Each pipeline stage is a Claude Agent SDK session with full
shell access. The category prompt carries the methodology (persona, OWASP workflow, scope,
evidence rules); the deep how-to for each tool lives in a **skill** — a folder whose
frontmatter (name + one-line "when to use") is always in context, but whose body loads **only
when the agent escalates to that tool** (*progressive disclosure*). This keeps the base prompt
lean while bringing tool depth just-in-time.

**5. Findings and diffs.** Agents emit **structured findings** (JSON schema) — category, CWE,
OWASP class, severity, confidence, evidence, a **safe PoC**, repro steps, the vulnerable
`file:line`, the missing defense, and a remediation. The worker streams them back to the
dashboard's sink after every agent (so a timeout never loses results). Each finding's **stable
fingerprint** drives the diff engine: `new`, `open`, `fixed`, or `regressed` across scans,
computed from Postgres' JSONB write-delta log.

### Pipeline stages

`pre-recon -> recon -> vulnerability-analysis -> exploitation -> reporting`

| Stage | Agents | Execution | Nature |
|---|---|---|---|
| **Prerequisites** | `pre-recon`, `recon` | Sequential, **fail-fast** | Discovery + whitebox surface mapping |
| **Vulnerability analysis** | `injection`, `xss`, `auth`, `ssrf`, `authz` | 5 agents, **2-wide concurrent** | Read-only / static (SAST, SCA, secrets) |
| **Exploitation** | `injection`, `xss`, `auth`, `ssrf`, `authz` | 5 agents, **2-wide concurrent** | Live DAST + harmless PoC |
| **Synthesis** | `report`, `attack-surface` | Best-effort | Executive report + kill-chain + fix prompts |

Within a parallel group a single agent failure is **isolated** — it is logged and the rest of
the group continues. Prerequisites are fail-fast because the vuln agents read their
deliverables. The split rule is firm: **static analyzers run in analysis (no live traffic);
DAST runs in exploitation.**

## Toolkit and Scope

The worker image preinstalls the offensive toolkit; **31 skills** document them (30 tools + one
`authz-recipe` procedure for the category with no headless CLI). Skills are tagged by pipeline
layer and grouped by attack category.

### Recon and discovery

| Tool | Role |
|---|---|
| subfinder, dnsx, naabu, nmap | Subdomain enum, DNS, port discovery, deep service scan |
| httpx, katana | Live HTTP probe/fingerprint, web crawl |
| gau, waybackurls, paramspider | Historical URL + archived-parameter mining |
| arjun | Active hidden-parameter discovery |
| wafw00f | WAF/CDN fingerprinting |
| ffuf | HTTP fuzzer (content / param / value; also auth + IDOR) |
| nuclei | Templated vuln/misconfig scan |

### Static analysis (whitebox, read-only)

| Tool | Role |
|---|---|
| semgrep | SAST — taint/pattern rules over the repo |
| gitleaks, trufflehog | Secrets in repo + git history (trufflehog verifies live) |
| osv-scanner | Dependency CVEs via OSV (software composition analysis) |

### Exploitation (live proof-of-concept)

| Category | Tools |
|---|---|
| **Injection** | sqlmap (SQL), commix (OS command), sstimap (SSTI), nosqli (NoSQL) |
| **XSS** | dalfox (primary), xsstrike (context-aware), kxss (reflected triage) |
| **Auth** | jwt_tool (alg:none / key confusion / crack), hydra (login brute), generate-totp (2FA) |
| **Authz / IDOR / BOLA** | authz-recipe (role x endpoint matrix + A/B session replay + ffuf ID enum) |
| **SSRF** | ssrfmap (exploitation modules), interactsh-client (out-of-band callback proof) |
| **Browser / DOM** | playwright (headless browser — auth flows + XSS execution proof) |

**Cross-cutting rules baked into every skill:** act only on hosts inside the validated Rules
of Engagement (re-checked before each network action); per-host rate limits (no-DoS); stop at
the **minimum-impact PoC**; redact secrets/PII in evidence; git-clone tools are pinned to a
`tools.lock` SHA for reproducibility.

## Repository Layout

```
apps/web/      Cloud Run SERVICE (shor-web): auth, data repositories, secrets,
               orchestration, ingest, findings/diff/SARIF, guardrails, share plane,
               and the static dashboard (apps/web/src/public/)
apps/worker/   Cloud Run JOB (shor-scan-worker): the Claude Agent SDK pipeline,
               session/agent definitions, audit + metrics, guardrails
skills/        31 per-tool skills loaded by the worker at runtime (progressive disclosure)
infra/docker/  Wolfi/glibc multi-stage toolkit image (~30 tools) + tools.lock;
               Dockerfile.web for the dashboard image
infra/config/  Shared TypeScript + Biome config
```

The monorepo uses **pnpm workspaces + Turborepo**; lint/format is **Biome**. Internal design,
research, and planning docs live under `docs/` and are intentionally **local-only (gitignored)**.

## Quick Start

Prerequisites: **Node 22+**, **pnpm 10.33+**, and (for the toolkit image) **Docker** on a
native `linux/amd64` builder.

```bash
pnpm install
pnpm build          # turbo: builds @shor/web and @shor/worker
pnpm check          # type-check both packages (tsc --noEmit)
```

<details>
<summary><b>Run the dashboard locally (no GCP needed)</b></summary>

Every config value has a safe default, so the web app type-checks and boots **without live
GCP credentials** — cloud SDK clients are constructed lazily on first use. For a local login
shortcut, enable the env-gated dev login (provisions a seeded dev tenant + user; **must stay
off in production**):

```bash
export SHOR_DEV_LOGIN=true
pnpm dashboard:dev          # tsx apps/web/src/index.ts  (hot path)
# or, after pnpm build:
pnpm dashboard              # node apps/web/dist/index.js
```

The server listens on `WEB_PORT` (default `8080`) and serves the UI from
`apps/web/src/public/`.
</details>

<details>
<summary><b>Apply database migrations</b></summary>

Migrations are idempotent SQL applied by a small runner; in production they run as the
`shor-migrate` Cloud Run Job. Locally, point `CLOUD_SQL_*` at a Postgres instance and:

```bash
pnpm --filter @shor/web build
node apps/web/dist/db/migrate.js
```

The schema models `tenant -> project -> codebase_ver -> scan -> { finding, attack_surface }`,
stores findings as JSONB, and (in production) enables a **pgMemento** delta log on `finding`
and `attack_surface` for scan-to-scan diffs. The migration degrades gracefully when pgMemento
is absent (local dev).
</details>

<details>
<summary><b>Build the dashboard image (shor-web)</b></summary>

Small Node image, no offensive toolkit. **Build context is the repo root** (it copies the
workspace manifests):

```bash
docker build -f infra/docker/Dockerfile.web -t shor-web:latest .
```
</details>

<details>
<summary><b>Build the offensive-toolkit image (shor-scan-worker)</b></summary>

A 4-stage Wolfi/**glibc** build (`go-builder -> py-builder -> runtime-staging -> runtime`)
producing a minimal, shell-less runtime with ~30 tools and a shared Python venv. **Build
context is `infra/docker/`.** Pass the pinned git-clone SHAs from `tools.lock` as build args
(a CI target should generate these from the lockfile):

```bash
docker build \
  --build-arg SQLMAP_SHA=...   --build-arg COMMIX_SHA=... \
  --build-arg SSTIMAP_SHA=...  --build-arg XSSTRIKE_SHA=... \
  --build-arg SSRFMAP_SHA=...  --build-arg JWT_TOOL_SHA=... \
  --build-arg NOSQLI_SHA=...   --build-arg PARAMSPIDER_SHA=... \
  -t shor-toolkit:latest \
  infra/docker

docker build --check infra/docker        # lint all stages, no build
```

Wolfi is **glibc** (not Alpine/musl), so PyPI wheels and CGO binaries install natively;
Playwright reuses the apk-provided Chromium (no second browser download). See
`infra/docker/README.md` for the full tool inventory and build-verification status.
</details>

## Usage

The happy path, control plane to fix:

1. **Sign in.** In production via Google Cloud **Identity Platform** (one IdP tenant per org);
   locally via the dev-login flag.
2. **Connect a repo and create a Project.** Connect GitHub (OAuth or PAT), pick a repo, set
   the **target URL**, choose **white-box** (clone repo) or **black-box** (URL-only), and
   optionally a cron schedule and target auth/ROE config.
3. **Trigger a scan.** The dashboard pins a CodebaseVersion, starts the Temporal workflow, and
   launches the per-scan Cloud Run Job.
4. **Watch live progress.** The run view shows the phase/agent timeline (which agents are
   running concurrently, which skills each has invoked) as the worker pushes updates.
5. **Review and remediate.** Each finding shows severity, confidence, evidence, the **safe
   PoC**, repro steps, the vulnerable `file:line`, and a remediation. Open the **attack-surface**
   scenarios (kill chains), compare against a prior scan in the **diff** view
   (new/open/fixed/regressed), **Copy fix prompt** for the repo, or **export SARIF**
   (`GET /export/sarif?scan=<id>`).

Owners can mint a **read-only share link** for a single project — an opaque slug that exposes
just that project's scans, findings, and diffs at `/share/:slug/...` with no login.

## Technical Details

### Data model

```
Tenant ─< Project ─< CodebaseVersion ─< Scan ─< { Finding, AttackSurface }
       └─< User        (4-role RBAC)
       └─< ProviderKey (key material in Secret Manager only)
```

| Entity | Notes |
|---|---|
| **Tenant** | One Identity Platform tenant per org; row-level tenant scoping on every query |
| **User** | Four-role RBAC: `owner` / `admin` / `member` / `viewer`; one tenant per user |
| **ProviderKey** | Per (tenant, user, provider) — `anthropic`/`openai`/`deepseek`/`openrouter`/`vertex`; the DB stores only a Secret Manager **reference**, never key material |
| **Project** | Target URL + connected repo + mode (`whitebox`/`blackbox`) + schedule + ROE; optional `shareSlug` |
| **CodebaseVersion** | Immutable snapshot per ingest (git SHA + GCS prefix) |
| **Scan** | One run; `pending`/`running`/`completed`/`failed`/`cancelled`; live progress snapshot (JSONB) |
| **Finding** | JSONB record + stable `fingerprint`; diff status `new`/`open`/`fixed`/`regressed` |
| **AttackSurface** | Kill-chain scenarios with a per-scenario remediation ("fix") prompt |

The **Finding** record (the contract the dashboard depends on) carries: `category`, `cwe`,
`owasp_category`, `severity` (`critical`..`info`), `confidence` (`confirmed`/`firm`/`tentative`),
`evidence`, `safe_poc`, `repro_steps[]`, `vulnerable_code_location {file,line}`,
`missing_defense`, `remediation`, and the load-bearing `fingerprint`
= `sha256(category + cwe + normalized_location + normalized_evidence)`.

### Guardrails (code-enforced, not prompt-only)

| Rail | Enforcement |
|---|---|
| **Rules of Engagement** | Per-target scope allowlist; checked before each run **and** before each network action |
| **Rate limit** | Per-host token bucket — no denial-of-service |
| **Egress** | Default-deny outbound allowlist (ROE hosts + GitHub); cloud metadata IP and internal ranges hard-blocked |
| **Redaction** | Secret / token / PII redactor over logs and evidence |
| **Kill switch** | Temporal cancellation + per-run teardown with blast-radius caps |
| **Audit** | Tamper-evident tee to Cloud Audit Logs + the delta log (redacted) |

### Isolation (defense-in-depth, one layer per axis)

**Compute** — one gVisor-sandboxed Cloud Run Job per scan. **Identity** — dedicated per-run
service account, secret access scoped to that tenant only. **Secrets** — mounted as volume
files (not env vars, to avoid `/proc/environ` leakage); only the one provider key for that run
is injected. **Filesystem** — ephemeral per-run workdir + per-tenant GCS prefix. **Network** —
per-tenant VPC egress firewall. **Temporal** — per-scan workflow IDs (`shor-<random>`) so
concurrent tenants never collide.

### Stack

| Area | Technology |
|---|---|
| Language / build | TypeScript (ESM), pnpm workspaces, Turborepo, Biome |
| Control plane (`apps/web`) | `@google-cloud/{run,secret-manager,storage}`, `@octokit/*`, `@temporalio/client`, `pg`, `google-auth-library` |
| Data plane (`apps/worker`) | `@anthropic-ai/claude-agent-sdk`, `@temporalio/*`, `ajv` + `zod` (schema validation), `zx`, `js-yaml` |
| Toolkit image | Wolfi `wolfi-base` builders -> `glibc-dynamic` runtime; shared Python venv; apk Chromium for Playwright |
| Cloud | Identity Platform, Temporal Cloud, Cloud Run (service + jobs), Cloud SQL (Postgres + pgMemento), Secret Manager, GCS |

### Key configuration

Resolved from the environment with safe defaults (importing config performs no I/O). The
operationally important variables:

| Variable | Purpose |
|---|---|
| `GCP_PROJECT_ID`, `GCP_REGION` | Core project + region |
| `CLOUD_SQL_*` | Postgres connection (Auth Proxy socket in Cloud Run, TCP locally) |
| `GCS_BUCKET` | Single artifact bucket (per-tenant prefixes) |
| `TEMPORAL_ADDRESS` / `_NAMESPACE` / `_TASK_QUEUE` / mTLS or `_API_KEY` | Temporal Cloud client |
| `CLOUD_RUN_SCAN_JOB`, `CLOUD_RUN_WORKER_IMAGE`, `CLOUD_RUN_*` | Per-scan job launch (identity template, CPU/memory, timeout, VPC egress) |
| `IDENTITY_PLATFORM_*`, `SESSION_SIGNING_SECRET` | Auth + the HMAC-signed session cookie (**set a strong secret in prod**) |
| `SHOR_PUBLIC_URL`, `SHOR_SINK_TOKEN` | Dashboard base URL + shared token the worker uses to post findings (**secret in prod**) |
| `GITHUB_APP_ID`, `GITHUB_OAUTH_CLIENT_ID` / `_SECRET` | GitHub App ingest + "Connect with GitHub" OAuth |
| `SHOR_DEV_LOGIN` | Local login shortcut — **must be `false` in production** |

The per-scan job additionally reads `SHOR_SCAN_ID`, `SHOR_TARGET_URL`, `SHOR_REPO_GCS_URI`
(absent for black-box), and `SHOR_PROVIDER_KEY_FILE` (the file path of the mounted key).

## Status and Roadmap

All build phases — the engine plus the cloud/multi-tenant shell — **compile end-to-end on
`main`** (`pnpm install` + `tsc` green). Live deployment needs a provisioned GCP project, an
authorized target, and an Anthropic API key.

Planned / not yet complete:

- **Real authentication.** The hosted dashboard currently runs behind the **dev-login
  prototype** (`SHOR_DEV_LOGIN`), a flag-gated placeholder that auto-provisions a fixed dev
  tenant. The deliberate **Identity Platform** flow is partially wired and is finished in its
  own work; dev-login is to be removed, never extended.
- **Guest share-access credential.** The read-only per-project share plane exists; the team's
  hardcoded guest-access credential is wired in server config at the end, not committed here.
- **Native toolkit-image CI.** The 4-stage build passes `docker build --check` and the Python
  builder is verified end-to-end; the large Go tools compile too slowly under local QEMU
  emulation to finish in-sandbox, so a **native `linux/amd64` CI build + per-tool smoke test**
  is the remaining acceptance gate.
- **Deferred tools.** masscan, rustscan, amass, feroxbuster, gobuster, dirsearch, medusa, and
  patator are non-blocking, post-launch image additions; the primary `*` tools already cover
  every pipeline layer.

## Disclaimer / Responsible Use

Shor is built for **defensive security and authorized testing only**. It must be pointed
exclusively at systems you own or are explicitly contracted to test, within a defined scope.
The platform enforces this in code — rules-of-engagement scope checks before every network
action, per-host rate limits, a default-deny egress allowlist, minimum-impact proofs-of-concept,
secret redaction, and a kill switch — but **those rails do not absolve the operator of
responsibility**. Running it against systems without authorization is illegal and unethical.

Active findings reflect a point-in-time scan and may include false positives or miss issues;
treat the output as input to human review, not a certificate of security.

## License

Source headers declare **GNU Affero General Public License v3.0** (AGPL-3.0-only), Copyright
(C) 2025 Keygraph, Inc.
