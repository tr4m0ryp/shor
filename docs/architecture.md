# Architecture — locked decisions

This captures the design discussion. Reference baseline is **storron**
(`/Users/macbookpro/projects/hackatron/storron`) — a pnpm/TypeScript monorepo:
`apps/web` (dashboard UI we keep), `apps/cli` (Docker orchestrator), `apps/worker`
(Temporal-orchestrated agent pipeline on the Claude Agent SDK).

## 1. Product intent

An autonomous AI pentester with a **company/enterprise surface**: users connect a
repository, register target websites, schedule re-scans, and review run history
and findings over time. Defensive / authorized-testing use only.

## 2. Decisions (settled)

| # | Decision | Choice |
|---|---|---|
| D1 | Codebase strategy | **Fresh repo, reuse modules** — port storron's prompts, SDK executor, and web dashboard as libraries; do not fork wholesale. |
| D2 | Agent ↔ tool model | **Rich system prompt + per-tool skills + preinstalled binaries.** Bash-driven execution; each tool documented as a loadable skill. |
| D3 | Deployment shape | ~~Single-tenant~~ → **Multi-tenant** (ADR-011). Multiple users, OAuth login, per-user model + API keys, per-user run isolation. |
| D4 | Tor / onion | **Removed entirely.** Drop onion egress, the tor-* services, onion prompts, and `--onionize`. |
| D5 | Findings recording | **SDK structured output** (JSON schema), as storron already does for its exploitation queue — feeds the findings DB, history, and diffs. |
| D6 | UI | **Reuse storron `apps/web`** dashboard + style verbatim (ADR-013); add Targets, multi-user, diff views. |
| D7 | Cloud | **Runs on GCP**; database is a **Google database** (ADR-012). Service choices → research skill. |
| D8 | Output schema | **Same as storron** (ranked findings + attack ideas); `claude_code_prompt` inverted to a **remediation/fix prompt** (ADR-010). |
| D9 | Open questions | **Delegated to the research skill** (web + storron-lens), not asked of the operator (ADR-014). |
| D10 | Project model | **Company → Project → CodebaseVersion → Scan** with retained codebase + scan history; GitHub-pull or upload per run (ADR-015, [`project-model.md`](project-model.md)). |

## 3. The agent ↔ tool model (the core idea)

storron already runs each category agent as a **Claude Agent SDK session with full
shell access and permissions bypassed** — so dedicated tools like `sqlmap` are
already invokable. What was missing: the tools aren't installed, and the prompts
don't teach when/how to use them. So this is **additive, not a rewrite**:

1. **Preinstall the toolkit** in the worker image (per category).
2. **Keep the rich category system prompts** (persona, methodology, OWASP
   workflow, scope, evidence rules) — ported from storron.
3. **Author one skill per tool.** A skill is a folder with `SKILL.md`
   (name + description always in context; deep body loaded on demand —
   *progressive disclosure*). The category prompt references the relevant skills
   by name; the agent pulls a skill's full body only when it escalates to that
   tool.

**Precedent in the reference:** storron already ships a `playwright-cli` skill and
its prompts say *"invoke the `playwright-cli` skill to learn available commands."*
We generalize that single pattern to every hacking tool.

Why skills over stuffing usage into the prompt: 20 deep tool guides would bloat the
base prompt and burn context every turn. Progressive disclosure keeps the rich
prompt intact and brings tool depth just-in-time.

### Skill file shape

```
skills/sqlmap/SKILL.md
---
name: sqlmap
description: Automate SQL/NoSQL injection confirmation + exploitation — flags,
  auth reuse, enumeration ladder, evidence capture, safe defaults. Use during
  injection exploitation when escalating past manual curl.
---
# body (on demand): --batch/--level/--risk, --cookie / -r request replay,
# --dbs → --tables → --dump --start 1 --stop 5, WAF tamper scripts, tee logs,
# scope + rate-limit guardrails.
```

### Prompt reference snippet (added to the ported category prompt)

```
<tool_skills>
Confirm by hand with curl first, then escalate:
- SQLi/NoSQLi → `sqlmap` skill   - OS command → `commix` skill
- SSTI       → `sstimap` skill   - path traversal/LFI → `ffuf` skill
</tool_skills>
```

## 4. Pipeline (kept from storron) and tool→layer mapping

`pre-recon → recon → vuln-analysis → exploitation → reporting`

| Layer | Nature | Candidate tools (to be confirmed by research) |
|---|---|---|
| Pre-recon / recon | discovery + whitebox | httpx, katana, nuclei, ffuf, subfinder, nmap, gau, arjun; semgrep (source) |
| Vuln analysis | **read-only, static** | semgrep (per-category rulesets), gitleaks, osv-scanner |
| Injection exploit | live | sqlmap, commix, sstimap, nosqli |
| XSS exploit | live | dalfox, xsstrike, kxss |
| Auth exploit | live | jwt_tool, ffuf, generate-totp |
| Authz exploit | live | ffuf + A/B session-replay recipe |
| SSRF exploit | live | ssrfmap, interactsh |
| Reporting | synthesis | — (structured output) |

Split rule: **static analyzers in analysis (no live traffic); DAST in exploitation.**

## 5. Enterprise features → architecture

- **Connect a repository / add a company** — a tenant adds a codebase as a named
  **Project** (e.g. avelero → `ddphosting`); we retain its **codebase versions**
  and **scan history**. GitHub-connected → new run pulls latest `main`; otherwise
  upload a new version. Full model in [`project-model.md`](project-model.md) (ADR-015).
- **Re-scans** — a new run pins a fresh CodebaseVersion + target URL. storron
  already runs scans as durable, resumable workflows, so re-scans reuse that engine.
- **History + diffs** — the real gap vs storron (which leans on the workflow event
  log + markdown deliverables). Add a datastore of runs / findings / evidence so
  the dashboard shows history and scan-to-scan diffs. Fed by D5 structured output.
- **UI** — reuse `apps/web` as-is.

## 6. What to strip when porting (Tor removal)

From storron: the onion + torsocks Docker builder stages; `apps/worker/src/ai/
tor-playwright/*`; `apps/worker/src/services/tor-*`; the `pre-recon-onion` prompt
and onion template selection; the CLI `--onionize` toggle and related compose.

## 7. Modules to reuse from storron (port targets)

- `apps/worker/src/ai/claude-executor/*` — the SDK execution loop.
- `apps/worker/src/services/prompt-manager/*` — `@include` + interpolation.
- `apps/worker/prompts/*` — category system prompts (minus onion).
- `apps/worker/src/session-manager/agents/*` — agent definitions per phase.
- `apps/web/*` — the dashboard UI.
- Temporal workflow/durability scaffolding (minus Tor preflight).
