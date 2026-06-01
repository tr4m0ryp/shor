# Cloud & Multi-Tenancy — decision-grade architecture research (GCP)

> Scope: multi-tenant, autonomous AI web-app pentesting platform ("Aegis") on
> Google Cloud, a fresh build reusing storron's TypeScript monorepo modules
> (web dashboard, CLI, Temporal-orchestrated Claude Agent SDK worker). Compares
> against storron's single-user patterns and recommends multi-tenant GCP
> extensions. No clarifying questions were asked; assumptions are stated inline.

## Stated assumptions (defaults)

- **Scale:** "small scale" = single GCP project (or one project per environment),
  low hundreds of monthly active users, tens of concurrent scans peak, each scan
  minutes-to-hours. Costs below are order-of-magnitude for this scale.
- **Region:** one primary region (e.g. `us-central1`); single-region HA is
  sufficient initially.
- **Trust model:** tenant *workloads* (the offensive tools the agent drives) are
  partly untrusted and target external/customer systems; tenants themselves are
  authenticated paying users, not anonymous internet.
- **Reuse mandate:** the storron `apps/web` dashboard, prompt/executor modules,
  and the Temporal-per-scan durability pattern are carried over (ADR-001, ADR-006,
  ADR-013); this report only changes the *hosting + multi-tenant* surface.
- **Currency:** pricing and product-tier facts verified against Google primary
  docs as of mid-2026; pricing is time-sensitive (see Caveats).

---

## 1. Multi-tenant auth (OAuth / OIDC)

**Recommendation: Google Cloud Identity Platform** (the paid upgrade of Firebase
Authentication), using its native **multi-tenancy** feature — one Identity
Platform *tenant* per Aegis customer org — for sign-in, session issuance, and the
isolation boundary. Self-host (Ory/Keycloak) only if you later need full control
of the identity data plane or want to avoid per-MAU billing.

**Why not base Firebase Auth:** Firebase Authentication **does not support
multi-tenancy** and supports **neither OIDC nor SAML** enterprise federation;
Identity Platform supports all three. Multi-tenancy and enterprise SSO are exactly
the two capabilities a multi-tenant security tool needs, and both are gated behind
the Identity Platform upgrade. (See findings F1.)

**Why managed over self-hosted (Ory Kratos/Hydra, Keycloak):** self-hosting buys
zero per-MAU cost and full control but adds a stateful HA service to operate
(DB, upgrades, key rotation, abuse handling) — directly against the "prefer
managed GCP services where they reduce ops burden" directive. Identity Platform
removes that burden and integrates natively with GCP IAM, Secret Manager, and
Cloud Run identity. Keep Ory/Keycloak as the documented fallback for a future
fully-self-hostable distribution.

**Session model:** Identity Platform issues short-lived ID tokens (JWTs, ~1h) plus
refresh tokens; the dashboard verifies the ID token server-side and mints its own
HTTP-only session cookie. The JWT carries the **tenant ID** and custom claims for
**RBAC** (e.g. `role: owner|admin|member|viewer`, `org: <tenantId>`). This is the
clean replacement for storron's effectively-absent per-user auth.

**Tenant / user isolation:** model each customer org as an Identity Platform
tenant; users belong to exactly one tenant; every API call and every scan is
scoped by the tenant claim. Application-layer authorization (row-level scoping in
the DB, per-tenant secret paths, per-tenant worker identity) enforces the boundary
— the auth provider supplies identity, not data isolation.

**Rough monthly cost at small scale:**

| Sign-in mix | Cost |
|---|---|
| Email/password + social/Google only (Tier 1), ≤ 50k MAU | **$0** (free tier) |
| Tier 1, 50k–100k MAU | $0.0055 / MAU/month (e.g. 60k MAU ≈ $55) |
| Enterprise SSO via SAML/OIDC (Tier 2) | $0.015 / MAU/month after a small free allowance — ~2.7× Tier 1, and effectively *much* more at small scale where Tier 1 is free |

For a few hundred Tier 1 users, **auth is effectively free**; enterprise SSO is the
only meaningful auth line item. (Findings F1, F2.)

---

## 2. Per-user config + secrets (BYO provider API keys)

**Recommendation: Google Secret Manager, one secret resource per (tenant, user,
provider) key**, with the **provider/model choice** stored as ordinary config in
the application DB (Postgres). Optionally layer **CMEK** (customer-managed
encryption keys via Cloud KMS) on the secrets for tenants demanding key custody.
This replaces storron's single-user `~/.storron/config.toml` (0600) with secure,
auditable, per-user storage.

**Why Secret Manager over a KMS-encrypted DB column / hand-rolled envelope
encryption:** Secret Manager already does what a DIY KMS-column scheme would
re-implement. It **encrypts all content at rest by default with Google-managed
keys** (envelope encryption built in, no CMEK setup required), gives per-secret
IAM, versioning, rotation, and audit logging for free, and integrates directly
with Cloud Run secret injection. A KMS-encrypted column means you own the
encrypt/decrypt path, version handling, and access logging yourself — more code,
more ways to leak. Choose the DB-column approach only if you have thousands of
keys per tenant and per-secret quota/cost becomes a factor. (Findings F3.)

**CMEK for high-assurance tenants:** when enabled, Secret Manager wraps each
secret version's **data encryption key (DEK)** with a customer-controlled
**symmetric Cloud KMS key (the KEK/CMEK key)** — true envelope encryption where the
customer can revoke the KEK to render secrets unreadable. Offer this per-tenant;
default to Google-managed keys. (Findings F3.)

**Safe injection into ephemeral workers — the load-bearing pattern:**

- Give each scan run a **dedicated, per-run service identity** (a service account)
  that holds `roles/secretmanager.secretAccessor` **bound on only that tenant's
  specific secrets**, not project-wide. This is the mechanism that scopes secret
  access per worker. (Findings F4.)
- **Mount secrets as volume files, not environment variables.** Volume mounts
  fetch the secret at read time (supporting rotation and avoiding the secret
  sitting in the process environment / crash dumps); env vars are resolved once at
  instance startup and are easier to leak via `/proc`, error reports, or child
  processes. Offensive tools spawn many child processes, so keeping provider keys
  off the environment materially reduces accidental exposure. (Findings F4.)
- Inject **only the one provider key the user selected for that run**, never the
  tenant's full keyset.

**Rough monthly cost at small scale:** Secret Manager is ~$0.06 per active secret
version per month plus ~$0.03 per 10k access operations. A few hundred users × a
handful of provider keys ≈ low single-digit dollars/month. CMEK adds Cloud KMS key
cost (~$0.06/key/month + per-operation) only for tenants who opt in. Effectively
**a few dollars/month** at this scale.

---

## 3. Per-user / per-tenant run isolation

**Recommendation: keep storron's "one Temporal workflow per scan on a
per-invocation task queue, executed in an ephemeral worker" pattern, and bind each
run to (a) a dedicated per-run service identity, (b) per-run scoped secrets, and
(c) a per-tenant network egress posture.** The storron pattern already gives
crash-resume and prevents per-scan repo cross-contamination; the multi-tenant
extension is *identity + secret + network* scoping per run, plus **kernel-level
sandboxing** because the workloads are partly untrusted.

**Isolation layers (defense in depth — no single mechanism suffices):**

1. **Compute isolation per run.** Run each scan in its own ephemeral VM-or-sandbox
   boundary (see §4): Cloud Run job instance, Cloud Batch per-job VM, or a
   gVisor-sandboxed GKE Pod. Per-job VM teardown (Cloud Batch) or gVisor
   (GKE Sandbox) gives the strongest isolation for untrusted offensive code.
2. **Identity isolation per run.** Dedicated service account per run (§2), so a
   compromised run can read only its own tenant's secrets.
3. **Filesystem isolation per run.** Ephemeral, per-run working dirs and cloned
   repos (storron already does this); artifacts pushed to a **per-tenant GCS
   prefix**, never a shared mount.
4. **Network isolation per run.** Per-tenant egress firewall rules via Direct VPC
   egress (each instance gets an internal VPC IP) so one tenant's scan cannot reach
   another's resources or the cloud metadata endpoint (§4, §7).

**On GKE specifically:** if you choose GKE, multi-tenant isolation must span
**five layers — cluster, namespace, node, Pod, container** — because no single
mechanism is a security boundary. Critically, **Pod anti-affinity and node
taints/tolerations are NOT security boundaries against malicious tenants** (a
hostile workload can relabel Pods or add tolerations to bypass them). The real
hardening layer is **GKE Sandbox (gVisor)**, which Google explicitly recommends
"for SaaS providers or organizations that run untrusted code" — exactly Aegis's
position — and which also blocks sandboxed Pods from the `169.254.169.254`
metadata endpoint by default. (Findings F5, F6.)

**Rough monthly cost:** isolation itself is mostly a configuration cost; the dollar
cost is the compute substrate (§4). gVisor adds CPU/network overhead (offensive
tools are network-heavy, so budget ~10–30% overhead) but no separate line item.

---

## 4. GCP compute for ephemeral Dockerized pentest workers

**Recommendation: Cloud Run *jobs* as the default worker substrate, with Cloud
Batch as the escape hatch for long (multi-hour) or strongest-VM-isolation runs.**
Run **Temporal on Temporal Cloud** to avoid operating a stateful cluster; self-host
on GKE only if data-residency or cost at scale demands it.

**Comparison for an ephemeral, Dockerized, outbound-internet, offensive-tool
worker lasting minutes-to-hours:**

| Option | Max runtime | Per-run isolation | Egress control | Concurrency | Cold start | Fit |
|---|---|---|---|---|---|---|
| **Cloud Run job** | up to 24h per task (configurable; default lower) | per-instance container; add gVisor-class hardening only via separate sandbox | **Direct VPC egress → internal IP + VPC firewall rules** | scales per execution, no servers | seconds | **Default.** Runs your existing Docker image; simplest ops; native Secret Manager mount + per-job identity |
| **Cloud Run service** | request/instance-bound, less suited to long batch work | per-instance container | Direct VPC egress (services & jobs both supported) | request-driven autoscale | seconds | Good for the dashboard/API, not long scans |
| **GCE MIG** | unbounded | per-VM (strong) | full VPC firewall | manual/auto scaling | minutes (VM boot) | More ops; only if you need custom VM images/GPUs |
| **GKE (+ Sandbox/gVisor)** | unbounded | **strongest via gVisor**, but requires the full 5-layer multi-tenancy discipline | NetworkPolicy + VPC | pod autoscale | seconds–minutes | Best isolation, highest ops burden; pick if you outgrow Cloud Run |
| **Cloud Batch** | long-running batch | **per-job dedicated VM(s) in a per-job MIG, auto created/deleted** → strong VM-level isolation | **per-job: `--no-external-ip` + `blockExternalNetwork` + VPC firewall** | per-job VMs | minutes (VM provision) | **Escape hatch** for hours-long scans needing VM-level isolation; runs script *or* container image as-is |

**Why Cloud Run jobs as default:** they run the existing storron Docker worker
image unchanged, scale to zero, mount Secret Manager secrets as files with a
per-job identity, and support **Direct VPC egress without a Serverless VPC Access
connector** — each instance gets an internal VPC IP, enabling per-instance/per-tenant
egress firewall rules. This covers the common minutes-to-low-hours scan with
minimal ops. (Findings F4, F7, F8.)

**Why Cloud Batch as the escape hatch:** each Batch job runs on a **regional MIG of
dedicated Compute Engine VMs that Batch auto-creates and deletes within the job
lifecycle**, giving per-job VM-level isolation that's stronger than a shared-kernel
container — ideal for the longest, most aggressive runs. Runnables can be a
**script or a container image**, so the same Dockerized tooling runs as-is. Egress
is restrictable per job (`--no-external-ip-address` and container-level
`blockExternalNetwork=true`, combined with VPC egress firewall rules) for
per-tenant network control. (Findings F8, F9.)

**Where to run Temporal:** **Temporal Cloud** (managed) is the low-ops default —
storron already depends on Temporal for durability/resume, and operating a
self-hosted Temporal cluster (Cassandra/Postgres + history/matching/frontend
services + HA) is a meaningful burden. Self-host on GKE/GCE only if Temporal
Cloud's data-residency, egress, or cost terms become blocking. The workers
(Cloud Run jobs / Batch) connect out to Temporal regardless of where it runs.

**Rough monthly cost at small scale:** Cloud Run jobs bill per vCPU-second and
GiB-second only while running; tens of multi-minute scans/day on 1–2 vCPU ≈ tens of
dollars/month. Cloud Batch adds the underlying CE VM cost for its (longer) jobs.
Temporal Cloud starts in the low tens of dollars/month at low action volume. Total
compute at this scale is plausibly **$50–150/month**, dominated by how many
hours-long scans run.

---

## 5. Google database for users, targets, runs, findings, and diffs

**Recommendation: Cloud SQL for PostgreSQL** (move to **AlloyDB** only if/when scan
volume and analytical/diff queries outgrow it). Postgres `JSONB` is the right fit
for the JSON-heavy findings schema (ranked vulnerabilities + attack-surface
scenarios), and it preserves storron's relational model for users/targets/runs.

**Why Postgres over Firestore:** the findings schema needs **rich
querying/filtering over nested JSON, relational joins (user → target → run →
finding), and scan-to-scan diffing** — all native to Postgres `JSONB` with GIN
indexes and SQL. Firestore is a document store optimized for real-time sync and
simple key/collection access, not ad-hoc JSON querying, joins, or historical
diffing; it would push diff logic into application code. Postgres keeps the
relational integrity storron's model already assumes.

**Why Cloud SQL first, AlloyDB later:** Cloud SQL is the lower-ops, lower-cost
managed Postgres and is sufficient at small scale; AlloyDB is Postgres-compatible
with stronger analytical/columnar performance and is the upgrade path if
diff/history queries over large finding histories become hot. Start simple.

**Scan-to-scan diffs / history — concrete pattern:** use **pgMemento**, which
implements a **PostgreSQL audit trail entirely in-database via triggers and
PL/pgSQL server-side functions** (no external service), logging **only the deltas
of each write into a single `JSONB` data-log table** (`pgmemento.row_log`) with
transaction/event metadata in separate tables. Delta-as-JSONB is *precisely* a
scan-to-scan change/diff store for a JSON-heavy findings schema — you get finding
history and diffs without building a bespoke versioning layer. This directly closes
storron's gap (markdown deliverables + Temporal event log, no queryable
history/diffs). (Findings F10.)

**Rough monthly cost at small scale:** a small Cloud SQL Postgres instance
(e.g. 1–2 vCPU, ~4 GiB, 20–50 GiB SSD, single-zone) runs roughly **$50–100/month**;
add a standby for HA to roughly double it. AlloyDB's minimum footprint is higher,
so defer it until justified.

---

## 6. Dashboard hosting

**Recommendation: Cloud Run *service*** for storron's reused Node web server (which
serves the static HTML dashboard, UI kept verbatim per ADR-013), fronted by the
Identity Platform auth from §1.

**Why:** it runs the existing Node server container unchanged, scales to zero,
gives HTTPS and a stable URL out of the box, shares the same Secret Manager + IAM +
VPC plumbing as the workers, and verifies Identity Platform ID tokens server-side
before minting the session cookie. Put it behind an external HTTPS load balancer /
Cloud Run domain mapping for a custom domain and, if desired, **Identity-Aware
Proxy or Cloud Armor** for an additional access/WAF layer in front of the
app-level auth. Static assets can sit on the same service or move to a GCS bucket +
CDN later; at this scale co-serving from the Node server is fine.

**Rough monthly cost at small scale:** a low-traffic always-warm-ish Cloud Run
service is a few dollars to low tens of dollars/month; scale-to-zero makes idle
cost near-nil. Load balancer (if used) adds ~$18+/month base.

---

## 7. Multi-tenant offensive-tool guardrails

This is the highest-risk surface: comparable AI pentest frameworks (e.g. HexStrike
AI) have been abused in the wild for real exploitation, so guardrails are a
first-class requirement, not an add-on. Anchor the controls to **OWASP APTS** (the
Autonomous Penetration Testing Standard) — a **governance standard (not a testing
methodology) defining what autonomous pentest platforms must do to operate safely
and within boundaries**. (Findings F11.)

**Map each guardrail to a managed GCP control and an APTS domain:**

| Guardrail | GCP mechanism | APTS domain |
|---|---|---|
| **Per-tenant egress control** | Direct VPC egress → per-instance internal IP + per-tenant **VPC egress firewall rules**; Cloud Batch `blockExternalNetwork` / `--no-external-ip`; sandboxed Pods auto-blocked from metadata endpoint | Safety Controls (sandbox network boundary) |
| **Prove per-tenant authorization-to-test** | Application-layer: machine-parseable Rules of Engagement per target (target list, time window, action restrictions) validated **before** each run and **immediately before each network action** | **Scope Enforcement (26 reqs)** — defining, validating, enforcing testing boundaries |
| **Rate-limiting / no-DoS** | Per-host connection/rate limits enforced in the worker + optional egress proxy; configurable per impact tier | **Safety Controls (20 reqs)** — blast-radius limits, per-host rate limiting |
| **Kill switch / rollback / blast radius** | Temporal workflow cancellation as the run-level kill switch; per-run teardown; per-run blast-radius caps | Safety Controls — kill switches, rollback, execution sandbox |
| **Execution sandbox** | gVisor (GKE Sandbox) or per-job VM (Cloud Batch) | Safety Controls SC-019 — kernel-enforced sandbox |
| **Secret redaction** | Keep provider keys off env (file-mount only, §2); redact secrets from logs/transcripts before persisting findings | Supply-Chain Trust — data handling |
| **Multi-tenant isolation of secrets/runs** | Per-run identity + per-tenant secret paths + per-run network/filesystem isolation (§2, §3) | **Supply-Chain Trust (22 reqs)** — "each customer engagement MUST run in an isolated execution environment with separation of memory, storage, network resources, and credentials" |
| **Tamper-proof audit / accountability** | Cloud Audit Logs + immutable findings/run records (pgMemento delta log); per-run action trail | APTS accountability + audit |

APTS explicitly enumerates **Scope Enforcement (26 requirements)**, **Safety
Controls (20 requirements)** (blast radius, kill switches, rollback, execution
sandbox), and **Third-Party & Supply-Chain Trust (22 requirements)** (multi-tenancy
isolation, AI-provider trust, data handling, foundation-model disclosure) — each
maps directly onto Aegis's authorization-to-test, no-DoS/egress, and per-tenant
secret/run isolation needs. Treat APTS as a governance *reference* (it is an early
v0.1.0 Incubator project with no certification body), not a certifiable trust mark.
(Findings F11, F12.)

**Rough monthly cost:** these are mostly configuration + application logic; the
priced pieces (VPC firewall, audit logging, the sandbox compute substrate) are
already counted in §3–§4. Budget engineering time, not dollars.

---

## Recommended reference architecture (text diagram)

```
                          ┌───────────────────────────────────────────────┐
   Users / Orgs           │  GCP project (region: us-central1)             │
   (browser, SSO)         │                                               │
        │                 │   ┌──────────────────────────────────────┐    │
        │  HTTPS           │   │ Identity Platform (multi-tenant)      │    │
        ▼                  │   │  - 1 tenant per customer org          │    │
   ┌─────────────┐  verify │   │  - OIDC/SAML SSO + email/social       │    │
   │ Cloud Run   │◄────────┼──▶│  - JWT: {tenantId, role} → RBAC       │    │
   │ SERVICE     │  ID tok  │   └──────────────────────────────────────┘    │
   │ (storron    │          │                                               │
   │  Node web   │  reads   │   ┌──────────────────────────────────────┐    │
   │  dashboard) │─────────▶│   │ Cloud SQL for PostgreSQL              │    │
   │  +IAP/Armor │  rows    │   │  users·targets·runs·findings (JSONB)  │    │
   └──────┬──────┘  scoped  │   │  + pgMemento JSONB delta log = diffs  │    │
          │ by tenant       │   └──────────────────────────────────────┘    │
          │ start scan                                                       │
          ▼                 │   ┌──────────────────────────────────────┐    │
   ┌─────────────┐  schedule│   │ Temporal Cloud (managed durability)   │    │
   │ Orchestrator│◄────────▶│   │  1 workflow per scan, crash-resume    │    │
   │ (Temporal   │          │   │  cancellation = run kill switch       │    │
   │  client)    │  dispatch└───┴──────────────────────────────────────┘    │
   └──────┬──────┘  per-run task queue                                       │
          │                                                                  │
          ▼  per run: dedicated service identity + scoped secrets            │
   ┌──────────────────────────────────────────────────────────────────┐     │
   │ EPHEMERAL WORKER  (default: Cloud Run JOB; long/hard: Cloud Batch  │     │
   │                    per-job VM; or GKE Sandbox/gVisor)              │     │
   │   • storron Docker image (sqlmap, nuclei, ffuf, …) unchanged       │     │
   │   • Secret Manager → secret MOUNTED AS FILE (one provider key)     │     │
   │   • per-run service account: secretAccessor on THIS tenant only    │     │
   │   • per-run ephemeral repo clone + working dir                     │     │
   │   • Direct VPC egress → internal VPC IP                            │     │
   └───────┬─────────────────────────┬───────────────────────┬─────────┘     │
           │ Secret Manager          │ VPC firewall          │ GCS           │
           ▼ (CMEK optional)         ▼ per-tenant egress      ▼ per-tenant    │
   ┌───────────────┐        ┌────────────────────┐   ┌──────────────────┐    │
   │ Secret Manager│        │ VPC + egress rules │   │ GCS (artifacts,  │    │
   │ per-(tenant,  │        │ no metadata access │   │  per-tenant       │    │
   │  user,provider)│       │ scope/rate guard    │   │  prefix)          │    │
   └───────────────┘        └─────────┬──────────┘   └──────────────────┘    │
                                      │ controlled outbound                  │
   ┌──────────────────────────────────┼──────────────────────────────────┐  │
   │ GUARDRAILS (OWASP APTS-aligned): per-run RoE check before every       │  │
   │ network action · per-host rate limits · secret redaction in logs ·    │  │
   │ Cloud Audit Logs · Temporal cancel kill-switch · blast-radius caps    │  │
   └───────────────────────────────────────────────────────────────────────┘ │
                                      │                                       │
                                      ▼  authorized target only               │
                              [ customer's web app under test ]               │
        └──────────────────────────────────────────────────────────────────┘
```

**One-line summary of the architecture:** authenticated and tenant-scoped at the
edge by **Identity Platform**, orchestrated durably by **Temporal Cloud**, executed
in **ephemeral Cloud Run jobs (Cloud Batch for the heavy/long runs)** that each get
a **dedicated identity + file-mounted Secret Manager keys + Direct-VPC-egress
network**, persisted to **Cloud SQL Postgres with a pgMemento JSONB delta log for
diffs**, and bounded by **OWASP-APTS-aligned scope/rate/redaction/kill-switch
guardrails**.

---

## Sources

1. Google Cloud — Identity Platform vs Firebase Authentication product comparison: https://docs.cloud.google.com/identity-platform/docs/product-comparison
2. Google Cloud — Identity Platform multi-tenancy authentication: https://docs.cloud.google.com/identity-platform/docs/multi-tenancy-authentication
3. Google Cloud — Identity Platform pricing: https://cloud.google.com/identity-platform/pricing
4. Google Cloud — Secret Manager CMEK (envelope encryption, DEK/KEK): https://cloud.google.com/secret-manager/docs/cmek
5. Google Cloud — Default encryption at rest (envelope encryption whitepaper): https://docs.cloud.google.com/docs/security/encryption/default-encryption
6. Google Cloud — Configure secrets for Cloud Run jobs (volume vs env, secretAccessor): https://cloud.google.com/run/docs/configuring/jobs/secrets
7. Google Cloud — Secret Manager access control (per-secret IAM binding): https://docs.cloud.google.com/secret-manager/docs/access-control
8. Google Cloud — GKE Sandbox (gVisor) sandbox pods: https://cloud.google.com/kubernetes-engine/docs/how-to/sandbox-pods
9. Google Cloud — GKE multi-tenancy overview (5 layers; anti-affinity/taints not security boundaries): https://docs.cloud.google.com/kubernetes-engine/docs/concepts/multitenancy-overview
10. Google Cloud — Direct VPC egress announcement (services & jobs, no connector, internal IP): https://cloud.google.com/blog/products/serverless/announcing-direct-vpc-egress-for-cloud-run
11. Google Cloud — Connecting Cloud Run to a VPC (Direct VPC egress, firewall by subnet/SA): https://docs.cloud.google.com/run/docs/configuring/connecting-vpc
12. Google Cloud — Cloud Batch create and run a job (per-job MIG, auto create/delete): https://docs.cloud.google.com/batch/docs/create-run-job
13. Google Cloud — Cloud Batch block external access for a job: https://docs.cloud.google.com/batch/docs/job-without-external-access
14. Google Cloud — Cloud Batch networking overview (blockExternalNetwork, no-external-ip): https://docs.cloud.google.com/batch/docs/networking-overview
15. pgMemento — in-database PostgreSQL audit trail (triggers/PL-pgSQL, JSONB delta log): https://github.com/pgMemento/pgMemento
16. pgMemento — DML logging (delta semantics): https://github.com/pgMemento/pgMemento/wiki/DML-logging
17. OWASP APTS — Autonomous Penetration Testing Standard (governance standard): https://owasp.org/APTS/
18. OWASP APTS — Introduction (governance framework, not a methodology): https://owasp.org/APTS/standard/Introduction.html
19. OWASP APTS — Checklists (Scope Enforcement SE-001…026, Safety SC-001…020, Supply-Chain TP-001…022): https://github.com/OWASP/APTS
