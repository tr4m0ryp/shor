# Research plan — questions to resolve before implementation

Research must converge these before we port code. Findings land in
`docs/research/`. Each question notes why it blocks a build decision.

## Standing principle — the storron lens (apply to EVERY item)

For every question and design decision below, **constantly compare against
storron**: (1) how does the reference do it today, (2) what's worth keeping vs
improving, (3) how do we combine the good parts with our new idea. This is not a
one-time review — it runs on every subsystem we touch. The living comparison
lives in [`research/storron-baseline.md`](research/storron-baseline.md); update it
and log an ADR whenever a subsystem is walked. storron stays read-only reference.

## A. Perfect tool selection (per category)

For each category: confirm the *de-facto standard* CLI tool(s), note actively
maintained vs abandoned, install method on a minimal glibc (Wolfi) image, whether
an AI-agent/MCP integration already exists, and licensing.

1. **Recon / discovery** — httpx, katana, nuclei, ffuf vs feroxbuster, subfinder,
   gau vs waybackurls, arjun vs paramspider, naabu vs nmap. Best blend?
2. **Static analysis (whitebox)** — semgrep (rulesets per category?), gitleaks vs
   trufflehog, osv-scanner vs grype. CodeQL worth the weight?
3. **Injection** — sqlmap (settled?), command-injection (commix?), SSTI
   (SSTImap vs tplmap — py3 + maintained?), NoSQLi (nosqli vs NoSQLMap).
4. **XSS** — dalfox vs XSStrike vs kxss; DOM/exec confirmation via Playwright.
5. **Auth** — jwt_tool (maintained?), HTTP brute (ffuf vs hydra vs patator),
   TOTP, OAuth/OIDC-specific tooling.
6. **Authz / access control** — is there a real tool, or is it replay-logic only
   (Autorize-style)? Best harness for IDOR/BOLA + privilege matrices.
7. **SSRF** — ssrfmap (maintained?), OOB/OAST (interactsh vs alternatives),
   gopher payloads, cloud-metadata recipes.

Deliverable: a confirmed toolkit table + Dockerfile install notes per tool.

## B. Best-fit integration / architecture designs

8. **Prior art in agentic pentest.** How do PentestGPT, Strix, XBOW, hexstrike-ai,
   CAI, Nebula, and similar wire LLM ↔ tools? What patterns win?
9. **Skills vs MCP vs typed tools.** Where's the line? Which actions deserve a
   typed/structured wrapper (findings) vs a Bash+skill (exploration)? Can the two
   coexist cleanly under the Claude Agent SDK?
10. **Structured findings.** Best schema for a finding (category, CWE, severity,
    evidence, repro, status) that supports scan-to-scan diffing.
11. **Scheduling + re-scans.** Temporal schedules vs external cron; how to make a
    re-scan a first-class, diffable entity.
12. **Repo connection.** GitHub app vs PAT; per-scan clone isolation; secret
    handling.
13. **Safety/guardrails.** Where to enforce in-scope-only, no-DoS rate limiting,
    and secret redaction — prompt vs tool boundary vs egress proxy.

## D. Cloud, multi-tenancy & per-user config (delegated to the research skill)

Operator requirement: multi-user on GCP. The research skill resolves these by
comparing storron + online research (ADR-011/012/014). storron's current single-
user patterns are noted for the storron lens.

14. **Multi-tenant auth (OAuth/OIDC).** Best approach for a self-hostable multi-
    user security tool on GCP: Google Identity Platform / Firebase Auth vs Auth0
    vs self-hosted (Ory/Keycloak). Session model, tenant isolation, RBAC basics.
15. **Per-user config + secrets.** Each user picks their own model + brings their
    own provider API keys (Anthropic/OpenAI/DeepSeek/…). Storage best practice —
    Google Secret Manager vs KMS-encrypted DB column — and safe injection into an
    isolated worker run. (storron stores one user's keys in `~/.storron/config.toml`
    `0600`; we need per-user.)
16. **Per-user run isolation.** storron runs each scan as a Temporal workflow in an
    ephemeral `docker run --rm` worker on a per-invocation task queue. Extend to
    per-user/tenant isolation on GCP so concurrent users never conflict.
17. **GCP compute for ephemeral Dockerized pentest workers** (need outbound net,
    run security tools, minutes–hours): Cloud Run (service vs job) vs GCE MIG vs
    GKE vs Batch — cost, isolation, egress, max runtime, concurrency. Where does
    Temporal run (self-host on GKE/GCE vs Temporal Cloud)?
18. **Google database** for users/targets/runs/findings + scan-to-scan diffs:
    Cloud SQL for PostgreSQL vs AlloyDB vs Firestore for a JSON-heavy findings
    schema. Recommend one.
19. **Dashboard hosting on GCP.** Serve storron's reused Node/static dashboard
    (keep the same UI style, ADR-013).
20. **Multi-tenant offensive-tool guardrails on GCP.** Egress control, per-tenant
    authorization-to-test, abuse prevention (cf. HexStrike real-world abuse).

## C. Open product questions (defer, not blocking)

- Product name (currently codename "aegis").
- Billing/quota per user (future).
