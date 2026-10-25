# Shor

<p align="center">
  <a href="https://x.com/tr4m0ryp"><img alt="Follow on X" src="https://img.shields.io/badge/X-@tr4m0ryp-000000?logo=x&logoColor=white"></a>
</p>

Shor is an autonomous offensive-security engine for web applications. You point it
at a target — a live URL, and optionally the source code behind it — and a team of
AI agents does what a human penetration tester would: map the app, reason about
where it's weak, try to break it, and **prove** each break by actually reproducing
it. Shor reports only findings it has validated, so what you get back is a short
list of real, exploitable bugs rather than a long list of maybes.

It runs as a multi-tenant platform: a web dashboard where you connect targets and
watch scans, and a per-scan worker that runs the agent pipeline in an isolated
sandbox. Everything a scan produces — findings, an attack-surface map, and a
written report — is stored as structured, diffable records you can share with a
read-only link.

---

## What Shor does, in one loop

Every scan follows the same idea, borrowed from how real attackers work and from
[XBOW](https://xbow.com)'s "prove it or drop it" discipline:

1. **Discover** the target — what services, pages, parameters, and technologies
   exist.
2. **Hypothesize** where the vulnerabilities are, one specialist per bug class.
3. **Challenge** each hypothesis with an adversarial jury before spending effort on it.
4. **Exploit** the survivors with real tools to see if the bug is actually there.
5. **Prove** it by replaying a harmless, reproducible proof-of-concept under a
   safety layer — no destructive payloads, no data loss.
6. **Refine** the results: remove duplicates, demote false positives, and write up
   only what held.

The guiding rule throughout: a finding is not real until Shor has reproduced it.

---

## How a scan runs — the agent pipeline

A scan is not one big model call. It's a pipeline of specialist agents, each its own
process running real command-line security tools. They hand structured deliverables
to the next stage. The phases run in this order:

| Phase | Agents | Runs | What happens |
|---|---|---|---|
| **Pre-recon → Recon → Threat-model** | 3 | sequentially | Map the live target (and the source, in white-box mode): services, ports, endpoints, parameters, tech stack. The threat-model agent turns that map into a prioritized list of where to look. |
| **Vulnerability analysis** | 7 | in parallel | One agent per bug class — injection, XSS, authentication, SSRF, authorization, business-logic, and web misconfiguration — each proposing candidate vulnerabilities in its domain. |
| **Adversarial screen** | a variable jury | in parallel | Each candidate finding is judged by several independent "voter" agents, each looking through a different lens (e.g. correctness, auth-context) and **blind to the recon context** so they can't be led. A majority vote decides which candidates advance. |
| **Exploitation** | 7 | in parallel | The same seven bug-class specialists take the pre-filtered, higher-confidence queue and try to actually exploit each surviving candidate against the live target, capturing a proof-of-concept for each. |
| **Proof replay (oracle)** | deterministic | after exploitation | Not an agent — Shor re-executes each captured proof-of-concept itself and lets the *observed* outcome override whatever the exploit agent claimed. A PoC that doesn't reproduce gets demoted; a low-confidence positive is never silently kept. |
| **Finalize** | 1 | sequentially | A single high-capability session runs three dependent stages — finding-refinement, then attack-surface, then report — to dedupe, demote, and write everything up. |

So a typical scan runs **about 17 specialist agents in fixed roles** — 3 for
discovery, 7 for analysis, 7 for exploitation — **plus a screening jury whose size
scales with how many candidate findings turn up**. In practice that's dozens of
independent agent invocations per scan, with tens of them running concurrently at
peak.

The seven bug classes get a dedicated agent in *both* the analysis and exploitation
phases, and each keeps its own isolated browser session so the parallel agents never
trip over each other's state.

---

## White-box vs. black-box scans

Whether a scan is white-box or black-box is a property of the **project**, decided
by whether you've connected source code to it.

**Black-box** — you give Shor only a **URL**. The pipeline runs entirely against the
live application, exactly like an external attacker with no inside knowledge. There's
no source code, so there's no static analysis and no code-level citation; findings
are grounded purely in how the app behaves and in a reproduced proof-of-concept.

**White-box** — you also connect the **source repository** (via a GitHub connection
or a zip upload). At scan time Shor clones the repo into an immutable snapshot and
gives the agents the code alongside the live target. This adds three things a
black-box scan can't have:

- **Source-grounded analysis.** Static-analysis tools (Semgrep, Gitleaks,
  TruffleHog, OSV-Scanner, Trivy) run over the actual code, and findings cite the
  exact file and line where the bug lives.
- **Actionable fixes.** Because every finding maps back to a place in your repo, the
  dashboard can hand you a ready-made "fix prompt" for that code.
- **Tracking across scans.** Findings are keyed to a stable fingerprint and to the
  code snapshot, so across a project's scan history you can tell which findings are
  new, recurring, or resolved.

Both modes run the **same agent pipeline and the same prove-it verification** — the
difference is how much context the agents start with and how precisely findings tie
back to your code.

---

## How findings are proven

Shor is built to fight false positives, because an autonomous scanner that cries wolf
is worse than useless. Three mechanisms keep the final list honest:

- **Proof-of-concept replay.** After exploitation, a deterministic oracle
  re-executes each captured proof-of-concept against the target — inside a
  code-enforced safety layer that blocks destructive actions — and the outcome it
  *observes* overrides whatever the agent claimed. A finding only counts as confirmed
  if its PoC actually reproduces.
- **Adversarial screening.** Before any exploitation effort, an independent jury of
  agents tries to *refute* each candidate; only majority-approved candidates advance.
- **A refinement gate at the end.** Findings carry independent evidence axes (is the
  code path confirmed, is the premise valid, is it in scope, is the location verified)
  that can only ever *lower* an over-confident label. Duplicates collapse into one
  canonical record, out-of-scope or single-identity "god-mode" artifacts are demoted
  rather than deleted, and boilerplate write-ups are caught. Nothing is silently
  dropped — demoted findings move to a review appendix.

---

## Memory (RAG) — opt-in

Shor ships a two-tier retrieval-memory layer so the engine can learn across scans.
It's an **opt-in capability** (feature-flagged, off by default), not an always-on
step, but the design is:

- A **per-project tier** remembers what's already been found in a given target, so
  repeat scans build on prior work instead of starting blank.
- A shared **knowledge tier** is pre-seeded with distilled attack-technique research
  (MITRE CAPEC plus recent web-security write-ups).

When enabled, this memory feeds the agents **ideas to try**, not verdicts to trust —
it broadens what the explorer thinks to attempt. The prove-it verification stays the
sole arbiter of what's real, and third-party research is treated as untrusted input
to guard against retrieval poisoning. Promotion of a finding into the shared,
cross-tenant tier is gated behind consent and mandatory secret/PII scrubbing.

---

## Tooling

Shor's agents don't just reason — they wield 30+ real offensive-security tools,
exposed to the model as invokable **skills**. Recon, exploitation, and static
analysis run on the same industry tooling a human pentester reaches for:

- **Recon:** nmap · naabu · httpx · katana · ffuf · arjun · paramspider · subfinder · dnsx · gau · waybackurls · kxss · wafw00f · nuclei
- **Exploitation:** sqlmap · commix · nosqli · xsstrike · dalfox · ssrfmap · sstimap · jwt_tool · hydra · interactsh-client · playwright
- **Static analysis (white-box):** semgrep · gitleaks · trufflehog · osv-scanner · trivy

---

## What a scan produces

- **Validated findings** — structured, severity-rated, deduplicated, and
  fingerprinted; in white-box mode, cited to exact source lines.
- **An attack-surface map** — the scenarios and kill-chains the agents explored, so
  you see how the app can be attacked, not just a bug list.
- **A written report** — a readable summary of what was found and how it was proven.
- **A read-only share link** — mint an opaque link to expose one project's scans,
  findings, attack surface, and progress to someone with no account.
- **SARIF export** and a project **scan history** — findings carry a stable
  fingerprint, so you can follow a given issue as new, recurring, or resolved across
  a project's runs.

---

## Running scans safely

Shor is for **authorized engagements only**. A scan enforces a signed **Rules of
Engagement** as a default-deny scope: the sandbox will only touch hosts you've
declared in scope, egress is firewalled per-tenant, and each scan runs in its own
isolated environment with its own scoped identity and secrets. When driven through
the automation/MCP surface, a scan can be started only with a single-use
authorization token that a human approver mints for that specific engagement —
there's no way for an agent to authorize itself. Cancelling a scan is the kill switch.

---

## Acknowledgements

Shor's discovery-and-verification pipeline ports ideas from Anthropic's defending-code reference harness, and its agent design follows Anthropic's *Building Effective Agents* patterns. It also builds on prior work in autonomous, validated penetration testing:

- **Anthropic — Defending code reference harness** — the discovery + verification pipeline Shor is based on ([repo](https://github.com/anthropics/defending-code-reference-harness), [Claude Code security](https://www.anthropic.com/news/claude-code-security)).
- **Anthropic — [Building Effective Agents](https://www.anthropic.com/research/building-effective-agents)** — the orchestrator-workers and evaluator–optimizer patterns the pipeline is built on.
- **[XBOW](https://xbow.com)** — validated, safe-PoC findings and its public challenge benchmark.
- **[PentestGPT](https://github.com/GreyDGL/PentestGPT)** — LLM-driven specialist-sub-agent pentest orchestration.
- **[Shannon](https://github.com/KeygraphHQ/shannon)** — open-source autonomous web-pentest agent.
- **Strix** and **HexStrike AI** — additional prior art in agentic penetration testing.

## License

Shor is **source-available**, licensed under the [PolyForm Noncommercial License 1.0.0](./LICENSE) — **not** an OSI open-source license.

- **You may** use, modify, fork, and share Shor freely for any **noncommercial** purpose, as long as you keep the copyright and `Required Notice:` lines (see [`NOTICE`](./NOTICE)) and credit *"Based on Shor by Keygraph, Inc."*
- **You may not** sell it, bundle it into a paid product, or run it as a paid/hosted service **without a commercial license**.

Copyright (c) 2025-2026 Keygraph, Inc. Commercial licensing enquiries: see [`NOTICE`](./NOTICE). Contributions are accepted under the [Contributor License Agreement](./CLA.md).
