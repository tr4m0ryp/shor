# Shor — Autonomous AI Pentester

Just like Shor's algorithm breaks encryption, **Shor** breaks your app's security — before someone else does.

An LLM-based pentester that runs 30 hacking tools simultaneously, reasons over the output, and hands you exploit PoCs and a written report. Point it at a URL and walk away.

> Optimised for Claude.

---

## How it works

Shor runs a phased agent pipeline on **Cloud Run Jobs** (one Job execution per scan).
Each agent is a Claude session with access to a curated toolkit of offensive security
tools. Agents hand deliverables to each other via a shared Git workspace.

```
pre-recon → recon → [injection | xss | auth | ssrf | authz] (parallel)
                  → [injection-exploit | xss-exploit | auth-exploit | ssrf-exploit | authz-exploit] (parallel)
                  → report + attack-surface (synthesis)
```

**White-box mode** additionally reads the full source code: static analysis (Semgrep,
Gitleaks, OSV-scanner), route enumeration, and auth-flow tracing before any live probe.

**Auth-aware scanning**: configure credentials once (`login_type`, `login_url`,
`credentials`) and every agent runs authenticated — no manual cookie juggling.

---

## Toolkit

**30 offensive tools** baked into the worker image:

| Category | Tools |
|---|---|
| Recon | httpx, subfinder, dnsx, naabu, nmap, katana, gau, waybackurls, arjun, paramspider, wafw00f, ffuf, nuclei |
| Static analysis | semgrep, gitleaks, trufflehog, osv-scanner |
| Injection | sqlmap, commix, sstimap, nosqli |
| XSS | dalfox, xsstrike, kxss |
| SSRF | ssrfmap, interactsh-client |
| Auth / session | ffuf, jwt_tool, nuclei |
| Browser | Playwright + Chromium (headless) |

---

## Infrastructure

| Component | Technology |
|---|---|
| Dashboard + control-plane API | Cloud Run **service** (`shor-web`) |
| Scan pipeline | Cloud Run **Job** per scan (`shor-scan-worker` / `shor-scan-worker-8gi`) |
| Database | Supabase Postgres |
| Repo staging | Google Cloud Storage |
| Secrets | Secret Manager (provider keys file-mounted, never in env) |
| AI provider | DeepSeek (agents) + Claude Code CLI (finalization) |
| Container base | Chainguard Wolfi/glibc — nonroot uid 65532, Gen2 execution environment |

**Two-image build split**: a slow base image (~30 min, rebuilt only when tools change)
and a fast app image (~2 min, rebuilt on every code change). Cloud Build has no layer
cache between builds; the split keeps iteration fast.

---

## Scanning a target

Use the external API (bearer-token authed):

```bash
# 1 — create project
curl -s -X POST "$SHOR_URL/external/projects" \
  -H "Authorization: Bearer $SHOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "My App", "targetUrl": "https://app.example.com",
       "mode": "whitebox", "repoRef": "owner/repo"}'

# 2 — start scan
curl -s -X POST "$SHOR_URL/external/scans" \
  -H "Authorization: Bearer $SHOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"projectId": "<id from step 1>"}'

# 3 — poll progress
curl -s "$SHOR_URL/external/scans/<scanId>" \
  -H "Authorization: Bearer $SHOR_TOKEN" | jq '{status, findingCount}'
```

Or use **`SHOR-SKILL.md`** — a Claude skill that walks the full setup interactively,
including deploying a pentest target on GCP, creating mock auth servers, and wiring
everything into Shor end-to-end.

---

## Repository layout

```
apps/
  web/        control-plane API + dashboard (Node.js, Cloud Run service)
  worker/     scan pipeline + agent execution (Node.js, Cloud Run Job)
infra/
  docker/     Dockerfiles (Dockerfile.base, Dockerfile, Dockerfile.web)
  config/     shared config
skills/       31 per-tool skill files loaded by the Agent SDK at runtime
.acceptance/  Cloud Build configs (cloudbuild.yaml, cloudbuild.web.yaml, cloudbuild.base.yaml)
SHOR-SKILL.md interactive Claude setup wizard (platform deploy + pentest project setup)
```

---

## Responsible use

**Authorized testing only.** Run Shor against systems you own or are contracted to
test. The agents are instructed to stay within the target URL's Rules of Engagement
and the control plane enforces this — but the responsibility for authorization is yours.
