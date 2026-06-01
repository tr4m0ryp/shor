# Output schema — replicate storron exactly, invert the Claude Code prompt

**Decision:** Aegis emits the **same output schema as storron** — detailed
**ranked vulnerabilities** plus **attack ideas** (scenarios + kill chains) — so the
reused dashboard renders unchanged. The **one deliberate change**: storron's
per-scenario `claude_code_prompt` is an *attack/reproduce* prompt; in Aegis it
becomes a **remediation prompt that fixes the issue in the company's codebase**.

Source of truth in storron:
`apps/worker/prompts/attack-surface.txt` (scenario + kill-chain schema, prompt
template) and `apps/web/src/api/workflows/findings/types.ts` (findings schema).
The dashboard reads it in `apps/web/src/public/index.html` (`renderAttackSurfacePanel`,
`renderAttackScenario`, `copyAttackPrompt`).

---

## 1. Findings — detailed vulnerabilities, ranked

Per-category (`injection | xss | auth | authz | ssrf`), each finding:

```
ID                       e.g. INJ-VULN-01   (pattern: [A-Z]+-VULN-\d+)
type                     injection | xss | auth | authz | ssrf
disposition              exploited | blocked | hypothesis
confidence               High | Medium | Low
externally_exploitable   bool
source_endpoint          where the input enters
vulnerable_code_location file:line  ← KEY for our remediation prompt
missing_defense          the absent/mismatched control (root cause)
exploitation_hypothesis  why/how it's exploitable
suggested_exploit_technique
notes
```

**Ranking / summary** (drives the Findings tab badges):

```
summary.byType[type] = { total, exploited, blocked, byConfidence{High,Medium,Low} }
summary.totals       = { total, exploited, blocked }
summary.reportAvailable, summary.attackSurfaceAvailable
```

Dispositions: `exploited` (proven), `blocked` (real but stopped by a control),
`hypothesis` (analysis-only, unproven). Ranking is by **severity → confidence →
disposition**. → **Keep verbatim.**

## 2. Attack Surface — the "attack ideas"

`attack_surface_scenarios.json = { scenarios:[], kill_chains:[] }`

**Scenario** (every field required, in order):

```
ID                       ATK-<NN>
title                    <= 80 chars, action-oriented
severity                 Critical | High | Medium | Low | Informational
business_impact          <= 600 chars, who is harmed and how
involved_findings        [ <VULN-ID>, ... ]
attack_chain[]           { step, action, tool, kill_chain_phase, mitre_attack, cwe }
preconditions            auth state / network position / prior knowledge
success_criteria         observable proof the chain worked
detection_signals        logs/traffic a defender should see
real_world_context       typical attacker profile
claude_code_prompt       ← INVERTED in Aegis (see §3)
estimated_effort_minutes 1–1440
exploit_unverified       bool
```

**Kill chain:** `{ ID: CHAIN-<NN>, title, involved_scenarios[], narrative, primary_mitre_tactics[] }`

Also emits a parallel `attack_surface_scenarios.md`. Empty-case rules exist
(emit a hypothetical scenario when nothing was proven). → **Keep verbatim.**

## 3. The Claude Code prompt — attack → remediation (our differentiator)

### storron today (attack / reproduce)
`claude_code_prompt` follows a fixed template: an AUTHORIZATION preamble, then
`Target / Scenario / Background / Goal: reproduce the reported behavior at <url>`,
concrete `Steps to reproduce` (exact commands / HTTP requests), `Tools needed`,
`Verification criteria`, and a mandatory `SAFETY` footer. It points the operator
at the **live target** to *confirm the attack*.

### Aegis (fix the codebase)
Same field, same slot in the schema, but the template targets the **connected
repository** and *resolves* the issue. Because Aegis connects the repo and the
finding already carries `vulnerable_code_location` (file:line) and
`missing_defense`, the fix prompt is concrete, not generic.

**Aegis `claude_code_prompt` template (remediation):**

```
REMEDIATION TASK — fix a confirmed security vulnerability in this repository.

Context: finding from an authorized assessment of <url>.
Finding: <VULN-ID> — <title>   (<severity>, <CWE>, category: <type>)

Where:        <vulnerable_code_location (file:line)>
Root cause:   <missing_defense — the unsanitized source→sink path / absent control>
Impact:       <business_impact>
Reproduction: <the validated PoC summary, for understanding only — do not re-run>

Fix requirements:
1. Apply the context-correct defense (e.g. parameterized query / output-encode
   for the sink context / enforce the authorization check at the boundary).
2. Apply the same fix to sibling code paths sharing this flaw.
3. Preserve existing behavior and public APIs; no unrelated changes.

Acceptance criteria:
- The previously-tainted input can no longer reach the sink unsanitized.
- Add a regression test asserting the fix.
- The category's static check (e.g. the matching semgrep rule) passes.

Do NOT weaken unrelated code, add needless dependencies, or change public APIs
unless the fix strictly requires it.
```

Notes:
- Keep an **authorization/context line** for filter-friendliness, reframed for
  defensive remediation rather than live attack.
- The button label flips from "Copy Claude Code prompt" (attack) to **"Copy fix
  prompt"** in the reused dashboard; the underlying field name `claude_code_prompt`
  can stay for schema compatibility, or be aliased `remediation_prompt`.
- This is the product story: storron hands you an attack to verify; **Aegis hands
  the company a paste-ready fix for their own repo.** Ties directly to ADR-005/007
  (validated finding + PoC) and the connected-repo architecture.

## 4. What this requires of the pipeline

- The **attack-surface agent** prompt is ported, with the `<claude_code_prompt_template>`
  block swapped for the remediation template above; it must read the finding's
  `vulnerable_code_location` + `missing_defense` from the queues.
- A new (or extended) **remediation step** may run after reporting to enrich each
  finding/scenario with the fix prompt using full repo context.
- Findings + scenarios persist to the datastore (ADR-005) so the dashboard shows
  ranked vulns, attack ideas, and the per-finding fix prompt — with history/diffs.
