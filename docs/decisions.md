# Decision log (ADR-style)

Short, dated records of architecture decisions. Date format: absolute.

## 2026-06-01 — ADR-001: Fresh repo, reuse storron modules
**Status:** accepted.
**Context:** New tool should build on storron's working pipeline + UI without
inheriting its full surface (esp. Tor).
**Decision:** New repo `aegis`; port prompts, SDK executor, prompt-manager, agent
defs, and the web dashboard as libraries. storron stays untouched as reference.

## 2026-06-01 — ADR-002: Rich prompt + per-tool skills + preinstalled binaries
**Status:** accepted.
**Context:** Want "advanced" tool-driven agents, not prompt-only. storron already
runs agents with full shell + bypassed permissions, so tools are invokable today;
only install + usage knowledge are missing.
**Decision:** Keep storron's detailed category prompts; preinstall per-category
tools; author one *skill* per tool (progressive disclosure). Prompts reference
skills by name. Generalizes storron's existing `playwright-cli` skill precedent.
**Consequences:** Additive, low-risk. No MCP required for execution. Structured
findings handled separately (ADR-005).

## 2026-06-01 — ADR-003: Single-tenant, self-hosted
**Status:** SUPERSEDED by ADR-011 (2026-06-01).
**Decision (superseded):** One org, hosted dashboard + scheduler + history.
Reversed: the product is now multi-user.

## 2026-06-01 — ADR-004: Remove Tor/onion entirely
**Status:** accepted.
**Decision:** Direct clearnet egress only (optionally a normal HTTP proxy). Drop
onion Docker stages, tor-* services, onion prompts, `--onionize`.

## 2026-06-01 — ADR-005: Findings via SDK structured output
**Status:** accepted.
**Context:** Dashboard history + scan-to-scan diffs need structured records, not
transcripts. storron already uses JSON-schema structured output for its
exploitation queue.
**Decision:** Record findings via SDK structured output into a datastore. Skills
do the work; structured output records it. Revisit a typed/MCP tool layer only if
research (Q9) shows it's warranted.

## 2026-06-01 — ADR-006: MCP scoped to connectivity only
**Status:** accepted (research-informed — see `research/tooling-and-integration.md`).
**Context:** Field splits into MCP-based vs direct-tool-calling schools; Anthropic
frames Skills (procedural) and MCP (connectivity) as orthogonal.
**Decision:** Run scanners via **shell + skills** (direct-tool-calling school).
Use **MCP only for connectivity** — GitHub repo connection and the findings
datastore — never to run sqlmap/dalfox/etc. A HexStrike-style typed tool layer is
optional future work, not required.

## 2026-06-01 — ADR-007: XBOW-style validated, safe-PoC findings
**Status:** accepted (research-informed).
**Context:** XBOW (#1 on HackerOne) and Strix both validate findings by running a
harmless PoC and emit reproducible scripts + remediation.
**Decision:** Every finding must carry a **safe, reproducible PoC** validated under
a safety layer, recorded as the structured record (ADR-005) that powers history +
scan-to-scan diffs. Schema to model on XBOW output + OWASP/CWE fields.

## 2026-06-01 — ADR-008: Guardrails enforced at the boundary, not the prompt
**Status:** accepted (research-informed).
**Context:** HexStrike AI was abused in the wild (Citrix zero-days) — prompt-level
scope rules are insufficient.
**Decision:** Enforce in-scope-only, no-DoS rate limiting, and secret redaction in
**code** (egress proxy / tool wrapper), with the prompt/skill as defense-in-depth.

## 2026-06-01 — ADR-010: Same output schema as storron; Claude Code prompt → remediation
**Status:** accepted. Detail in [`research/output-schema.md`](research/output-schema.md).
**Context:** storron emits ranked vulnerabilities (findings) + attack ideas
(scenarios/kill-chains), and each scenario carries a `claude_code_prompt` that
*reproduces the attack* at the live target.
**Decision:** Aegis replicates the **exact same output schema** (so the reused
dashboard is unchanged) with **one inversion**: the per-scenario `claude_code_prompt`
becomes a **remediation prompt that fixes the issue in the connected codebase**,
using the finding's `vulnerable_code_location` (file:line) + `missing_defense`.
Dashboard button flips "Copy Claude Code prompt" → "Copy fix prompt".
**Consequences:** Differentiator ("attack to verify" → "paste-ready fix"). Requires
porting the attack-surface agent prompt with the template swapped, plus repo
context at remediation time.

## 2026-06-01 — ADR-009: Storron-lens as standing research methodology
**Status:** accepted.
**Context:** storron is a working, battle-tested reference; we should mine it
continuously rather than design in a vacuum.
**Decision:** Every research item and subsystem design must **constantly** ask:
how does storron do it → what to keep/improve → how to combine with our idea.
Captured in the living [`research/storron-baseline.md`](research/storron-baseline.md);
each subsystem walked gets a baseline row + an ADR. Not a one-time review.

## 2026-06-01 — ADR-015: Project model — codebase versions + scan history
**Status:** accepted. Detail in [`project-model.md`](project-model.md).
**Context:** Company-centric tool. A tenant adds a codebase as a named Project
(e.g. avelero → `ddphosting`) and must retain codebase versions + past scans, and
re-run over time.
**Decision:** Model `Tenant → Project → CodebaseVersion → Scan → {Findings,
AttackSurface}`. A Project connects **GitHub** (new run pulls latest `main` into a
pinned CodebaseVersion) **or** takes **manual zip uploads** (new version per run).
Older versions + scans are retained (the history); each scan pins the exact code
it ran on. Code artifacts in **per-tenant object storage (GCS)**; metadata in the
Google DB. Reuse storron's `uploads/git.ts` + `uploads/zip.ts` as the ingest step.
**Consequences:** Enables project-scoped scan-to-scan diffs (ADR-010); informs the
DB schema (research Q18) and the GitHub-connection mechanism (research Q12).

## 2026-06-01 — ADR-011: Multi-tenant, OAuth, per-user config & run isolation
**Status:** accepted (requirement). Design specifics delegated to the research skill.
**Context:** Reverses ADR-003. The platform serves multiple users who must not
conflict; each user brings their own model + API keys.
**Decision:**
- **OAuth/OIDC login**; per-user accounts with isolation so one user's scans,
  targets, logs, and config never touch another's.
- **Per-user configuration:** own model choice + own provider API keys, stored
  securely (mechanism per research — Secret Manager vs KMS-encrypted column).
- **Per-user/tenant run isolation:** extend storron's per-scan ephemeral worker
  model so concurrent users' runs are isolated end to end.
**Open (→ research skill):** OAuth provider, session model, RBAC depth, secret store.

## 2026-06-01 — ADR-012: Runs on Google Cloud; database on Google
**Status:** accepted (requirement). Service choices delegated to the research skill.
**Decision:** Compute (web + ephemeral pentest workers + Temporal) runs on **GCP**;
the datastore is a **Google database**. Specific services (Cloud Run vs GCE vs GKE
vs Batch; Cloud SQL Postgres vs AlloyDB vs Firestore; Temporal Cloud vs self-host)
to be chosen by research with cost/isolation/egress/runtime trade-offs.

## 2026-06-01 — ADR-013: Keep storron's UI style
**Status:** accepted.
**Decision:** Reuse storron's dashboard look-and-feel verbatim (`apps/web`), only
adding Targets, multi-user, and diff views. No visual redesign.

## 2026-06-01 — ADR-014: Open questions resolved by the research skill
**Status:** accepted (process).
**Context:** Operator wants the research skill to figure out the open details
itself — by comparing storron and doing online research — instead of being asked.
**Decision:** All "OPEN" items below are delegated to the research skill (web +
storron-lens). Findings land in `research/`; each resolved item becomes an ADR.

## 2026-06-01 — Cloud ADRs (resolved by deep-research; see `research/cloud-and-multitenancy.md`)

**ADR-016 — Auth: Google Cloud Identity Platform.** One tenant per customer org;
OIDC/SAML SSO + email/social; `{tenantId, role}` claims in the session JWT drive
RBAC. (Base Firebase Auth lacks multi-tenancy + enterprise federation.) ~Free at
small scale. Resolves the auth open item.

**ADR-017 — Secrets: Google Secret Manager.** One secret per (tenant, user,
provider); **mounted as a file** (not env), optional CMEK. Each run gets a
**dedicated service identity** with `secretAccessor` bound to **that tenant's
secrets only**; inject just the one provider key the user selected. Replaces
storron's single `~/.storron/config.toml`.

**ADR-018 — Compute: ephemeral Cloud Run jobs (default).** Run storron's Docker
image unchanged, per-run identity + scoped secrets + **Direct VPC egress**.
**Cloud Batch** per-job VM for long/strongest-isolation runs; **GKE Sandbox
(gVisor)** if isolation needs outgrow Cloud Run. Resolves compute + run-isolation.

**ADR-019 — Durability: Temporal Cloud.** One workflow per scan, crash-resume;
**cancellation = per-run kill switch**. (Managed; avoids self-hosting Temporal.)

**ADR-020 — Database: Cloud SQL for PostgreSQL.** JSONB for the findings schema +
**pgMemento JSONB delta log** for scan-to-scan diffs/history. AlloyDB later if
scale needs it; **not Firestore** (poor for joins/diffing). Resolves the DB item.

**ADR-021 — Dashboard: storron Node server on Cloud Run**, behind Identity
Platform (IAP/Cloud Armor). Keeps the UI (ADR-013).

**ADR-022 — Guardrails: OWASP-APTS-aligned, enforced in infra.** Per-run
rules-of-engagement check before each network action, per-host rate limits, secret
redaction in logs, Cloud Audit Logs, Temporal cancel kill-switch, per-tenant VPC
egress rules (no metadata access), per-tenant GCS prefix. (cf. HexStrike abuse.)

Integrated reference architecture: `research/cloud-and-multitenancy.md` §"Recommended
reference architecture".

## OPEN — in-progress in the `/research` finalization (nested deep-research)
- Per-tool install method on minimal Wolfi/glibc image (git-clone vs go/pip).
- Borrow HexStrike's wrapper layer vs author skills fresh.
- Exact finding JSON schema (model on SARIF / DefectDojo / XBOW for diffability).
- Final integration-model verification (rich prompt + skill + shell vs MCP).
→ All resolve into `docs/LAUNCH-SPEC.md` when the finalization workflow completes.
