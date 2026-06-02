# Aegis

**An autonomous, multi-tenant AI pentester for web apps and APIs.**

A customer connects a target (live URL + the source repo via a GitHub App or a zip
upload); Aegis runs an LLM-driven agent pipeline — pre-recon → recon → vuln-analysis
→ exploitation → reporting — that drives ~30 preinstalled offensive tools through a
rich system prompt plus per-tool skills. Findings are validated with a harmless PoC,
stored as diffable records, and surfaced in a dashboard with a one-click **fix prompt**
for the connected repo. Built on Google Cloud (Identity Platform, Temporal Cloud,
Cloud Run, Cloud SQL, Secret Manager, GCS).

> Defensive / authorized-testing use only.

## Highlights

- **Multi-tenant** — Identity Platform auth, per-org tenancy, 4-role RBAC, per-user
  bring-your-own model + API keys in Secret Manager.
- **Per-scan isolation** — each scan runs as a Cloud Run Job (gVisor) launched by a
  Temporal Cloud workflow; per-run identity, file-mounted secrets, default-deny egress.
- **Tool-driven agents** — preinstalled toolkit (sqlmap, dalfox, nuclei, …) + a
  per-tool skill each; no Tor, clearnet only.
- **Findings & diffs** — stable-fingerprint records, scan-to-scan diffs
  (new/open/fixed/regressed), SARIF export, and an "attack → fix" remediation prompt.
- **Guardrails in code** — rules-of-engagement checks, rate limits, egress allowlist,
  secret redaction, kill switch, audit.

## Layout

```
apps/web/      Cloud Run service: auth, data, secrets, orchestration, ingest,
               findings, guardrails, dashboard
apps/worker/   per-scan job: the Claude Agent SDK pipeline + the de-Tor'd engine
skills/        per-tool skills (loaded by the worker at runtime) + authz recipe
infra/docker/  Wolfi multi-stage toolkit image (~30 tools) + tools.lock
```

Internal design / research / planning docs live under `docs/` (gitignored,
local-only). Start there at `docs/spec/LAUNCH-SPEC.md`.

## Status

All build phases (engine + cloud/multi-tenant shell) compile end-to-end on `main`.
Live deployment needs a provisioned GCP project + an authorized target; see the
implementation log in `docs/spec/LAUNCH-SPEC.md`.
