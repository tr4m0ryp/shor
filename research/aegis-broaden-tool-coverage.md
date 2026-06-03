# Broaden agent tool coverage -- Technical Design
# Started: 2026-06-03
# Source vision: none -- ran from topic (diagnosis built in the originating session)

## Brief

aegis runs an LLM-driven pentest pipeline (Claude Agent SDK 0.2.141; phases
pre-recon -> recon -> 5 parallel vuln->exploit pipelines -> reporting). ~30 offensive
binaries are wrapped as `SKILL.md` progressive-disclosure guides and executed as
Bash calls; an existing `skillTracker` records which tool each agent invoked.

**Symptom:** a run often calls only ONE hacking tool per phase (sometimes zero). We
want agents stimulated to try as many *applicable* tools/techniques as possible
("full skill" runs), without spraying every tool at every parameter or breaching
no-DoS / cost ceilings.

This doc resolves: how to enforce/encourage broad tool coverage (T1); where coverage
criteria live (T2); how to make a one-shot agent "keep going" (T3); how this
interacts with the existing Temporal retry/validator path (T4); breadth-vs-cost
guardrails (T5); whether to add planner fan-out (T6); how to verify and prevent
regression (T7); and the default thresholds (T8).

Out of scope / non-goals: changing the offensive toolkit itself; semantic skill
descriptions (already graded B, no collisions -- not the cause); replacing Temporal
or the SDK; running the actual implementation (that is `/readyforlaunch`).

## Recommended Technical Design

Treat "use more tools" as an **evaluator-optimizer loop** (Anthropic's canonical
pattern, R3) built on aegis's own instrumentation, layered cheap-to-expensive:

1. **Coverage policy (the criterion).** A declarative per-agent map -- `candidates`,
   `required`/`alwaysTry`, and a `minCount` floor -- co-located with the existing
   `RECOMMENDED` table. "Explore more" is meaningless without an explicit target; this
   is it.

2. **Prompt-level breadth scaffolding (prevention).** Upgrade the recommended-skills
   footer from a soft list into an explicit **tool checklist** the agent must seed into
   its TodoWrite plan (one todo per applicable tool, each marked ran / skipped+reason),
   plus a **breadth-before-depth** rule (run the full surface chain before deep-diving
   one finding) and a **justify-every-skip** rule. Cheap; reduces how often the gate fires.

3. **Coverage gate + continuation (the core fix).** After an agent's one-shot
   `query()` returns, read `skillTracker.skillsFor(agent)` and compare to the policy.
   If under the floor, do NOT full-retry -- fire a **bounded continuation**: a second
   `query()` seeded with the prior result plus "you ran {ran}; you did NOT run
   {missing}; run them now against the in-scope targets, or justify in one line why each
   is genuinely inapplicable." Loop up to `maxCoverageRounds` (default 2), accumulating
   tracked usage, bounded by the existing spending-cap safeguard. This converts
   "only 1 tool" into "ran the applicable set, or explicitly justified each skip."

4. **Observability + guardrails.** Emit per-phase coverage (ran / missing / skipped+why)
   to the dashboard via the existing progress emitter; bound breadth by a per-phase
   tool-call budget and the per-host rate limits already baked into each skill.

5. **Verification (anti-regression).** A canary CI scan against the bundled vulnerable
   fixture (`.acceptance/avelero`) that asserts via `skillTracker` that recon ran >=N
   tools and each exploit agent fired its category tool; plus a runtime **discovery
   preflight** (skills actually discovered + binaries on PATH) and `skill-issue` in CI.

Everything is **extend/build inside aegis** -- no new runtime dependency. The gate
reuses `skillTracker`, the watchdog turn-instrumentation, the post-execution hook, and
Temporal as the outer safety net.

## Decisions

### T1: How do we make agents use more tools?
**Decision:** Evaluator-optimizer **coverage gate with in-process re-prompt**, backed
by an explicit per-agent coverage policy, with prompt scaffolding as the first line of
defense. Not prompt pressure alone; not blind full-retry.
**Why:** Prompt pressure is already deployed (the recon prompt's "MANDATORY, run live
recon FIRST ... code reading is a FAILED recon" is scar tissue from exactly this
symptom) and is demonstrably insufficient. The literature (F1, R2) shows LLM agents do
not explore robustly without explicit intervention. Evaluator-optimizer (R3) is the
right shape because aegis already has a perfect, cheap evaluator signal: `skillTracker`.
**Alternatives rejected:** (a) Heavier system-prompt pressure -- same lever that already
failed. (b) Temporal whole-agent retry on low coverage -- wasteful and re-runs the same
behavior from scratch (F4). (c) Hard-wiring every tool to always run -- violates the
explicit "do NOT spray every tool at every parameter" rule and the no-DoS budget (T5).
**Confidence:** High.

### T2: Where do coverage criteria live?
**Decision:** A new `coverage-policy` map co-located with `RECOMMENDED` in
`apps/worker/src/services/prompt-manager/skill-recommendations.ts:26-39`, keyed the same
way, defining per template `{ candidates, required, minCount }`.
**Why:** That file is already the single source of per-agent tool scoping; the policy is
the same data with thresholds added. Keeping them adjacent prevents drift.
**Alternatives rejected:** A separate config file (splits the one place humans edit tool
scope); per-prompt frontmatter in the `.txt` templates (no frontmatter convention there).
**Confidence:** High.

### T3: How does a one-shot agent "keep going"?
**Decision:** A **continuation wrapper** around the single-pass executor that captures
the result, builds a follow-up prompt (prior result + missing-tool list), and invokes
the message stream again for up to `maxCoverageRounds`, accumulating `skillTracker`
usage across rounds.
**Why:** The SDK `query()` is one-shot -- the async generator ends on the `result`
message and exposes no resume (seam map; F2). The documented pattern is a sequential
second `query()` chaining prior context. `runClaudePrompt()` is single-pass today, so a
thin loop wrapper is the minimal change; `processMessageStream()` is already re-callable.
**Alternatives rejected:** SDK session resume (does not exist at 0.2.141); injecting
turns into the running generator (not supported -- can only break the loop, which the
watchdog already does).
**Confidence:** High.

### T4: Interaction with the existing validator -> Temporal retry path?
**Decision:** Coverage shortfall triggers **in-process continuation rounds first**, not
a Temporal whole-agent retry. Only if coverage is still below a *hard-required* floor
after `maxCoverageRounds` do we surface a failure to the existing
`validateDeliverable()` -> Temporal `OutputValidationError` retry path.
**Why:** Full-retry discards all prior progress and tends to reproduce the same
single-tool behavior; continuation preserves context and is strictly cheaper. Temporal
stays the last-resort net for genuine failure, unchanged.
**Alternatives rejected:** Fold coverage entirely into `AGENT_VALIDATORS` (would make
every shortfall a full restart -- the wasteful path we are avoiding).
**Confidence:** Medium-High (depends on continuation actually changing behavior; the
canary test in T7 measures this).

### T5: Breadth vs cost / no-DoS?
**Decision:** The "required" set is the **applicable subset given the queue/target**,
not all candidates; the gate honors (a) per-host rate limits already in each skill, (b) a
per-phase tool-call/token budget, and (c) the existing spending-cap safeguard. Skips are
allowed *with a specific reason*; only `required` tools cannot be silently skipped.
**Why:** There is a measured comprehension-vs-efficiency trade-off (F3, R4): exhaustive
exploration must be bounded. The prompts already forbid spraying. Bounded breadth + cheap
early tools first matches MAXS/ToolChain* cost control (R4).
**Confidence:** High.

### T6: Add planner-forced fan-out (orchestrator-workers)?
**Decision:** **Optional, recon-only, default OFF.** Ship the gate as the default
mechanism; offer a flag to decompose recon into one parallel sub-run per applicable tool.
**Why:** Structural breadth (one worker per tool) is the most robust way to guarantee
coverage (R3, R5) but the costliest. Recon benefits most -- its tool set is large and the
tools are independent. Exploit phases are queue-driven and per-category, so the gate is a
better fit there. Seam exists cleanly (`vuln-exploit.ts:183` / new activity).
**Alternatives rejected:** Fan-out everywhere (cost blow-up; redundant for narrow
queue-driven exploit agents).
**Confidence:** Medium.

### T7: Verification / regression prevention?
**Decision:** Three checks. (1) **Canary CI scan** against `.acceptance/avelero`
asserting via `skillTracker.all()` that recon ran >= floor tools and each exploit agent
invoked its category tool. (2) **Runtime discovery preflight** in the worker: assert all
expected skills were discovered by the SDK and every tool binary resolves on PATH; fail
loud otherwise. (3) `skill-issue skills/ --fix` for the one real description gap (missing
"Use when") + `skill-issue --json` as a CI gate.
**Why:** The symptom is silent today; only an assertion on observed tool usage catches
it (this is skill-issue's own v2 "agent-loop replay" idea, and the XBOW-style eval
approach, R1). The preflight catches the adjacent discovery/env failure mode from the
prior diagnosis.
**Confidence:** High.

### T8: Default thresholds (preference-sensitive -- see "Decisions Made For You").
**Decision:** `maxCoverageRounds = 2`; recon floor = probe >= 6 of the recon candidate
set (or justify); each exploit agent must run its matching category tool against every
actionable queue entry (or justify per entry). Tunable in `/refine`.
**Confidence:** Medium (defaults; designed to be cheap to change -- all live in one map).

## Stack & Libraries

No new runtime dependency. All work is **build/extend within `apps/worker`** in the
existing TypeScript + Temporal + Claude Agent SDK stack.

| Component | Call | Notes |
|---|---|---|
| Coverage policy + evaluator | Build | ~1 small module beside `skill-recommendations.ts`; pure, unit-testable. |
| Continuation wrapper | Extend | Thin loop around `runClaudePrompt` / `processMessageStream` (one-shot today). |
| Coverage read | Adopt | `skillTracker.skillsFor(agent)` / `.all()` already exist and are live mid-run. |
| Prompt checklist footer | Extend | Upgrade `recommendedSkillsSection()`. |
| Dashboard emission | Adopt | Existing progress emitter already ships `skills: skillTracker.all()`. |
| Discovery preflight | Build | Beside existing `services/preflight/`. |
| skill-issue gate | Adopt | External CLI already analyzed; `--fix` + `--json`. License MIT. |
| Canary eval | Build | New Temporal-free test harness over the bundled fixture. |

## Architecture

```
                     prompt-manager
  RECOMMENDED  ──┬──► recommendedSkillsSection()  ──► [checklist + breadth + justify footer]
  COVERAGE_POLICY┘                                         │ appended in loader.ts:109
        │                                                  ▼
        │                                          agent prompt (.txt)
        │                                                  │
        ▼                                                  ▼
   coverage evaluator  ◄────── skillTracker.skillsFor(agent) ◄── dispatch.ts:83 (tool_use)
        │  { ok, ran[], missing[], floor }                       (live, per agent)
        ▼
   COVERAGE LOOP (new wrapper around agent execution)
     round 0: runClaudePrompt(prompt)            ── one-shot query()
     evaluate ─► ok? ──► done
              └► under floor & rounds<max ─► runClaudePrompt(followUp(result, missing))
     still under hard-required after max ─► validateDeliverable() fail ─► Temporal retry
```

**Key interfaces/contracts:**

- `CoveragePolicy = { candidates: string[]; required: string[]; minCount: number }`,
  keyed by **agentName** (e.g. `injection-exploit`). NOTE the reconciliation point
  below.
- `evaluateCoverage(agentName, policy) -> { ok: boolean; ran: string[]; missing: string[];
  hardMissing: string[] }`, reading `skillTracker.skillsFor(agentName)`.
- `buildCoverageFollowUp(priorResult, missing, target) -> string` -- the re-prompt body.
- Continuation wrapper return aggregates rounds: total tools used, rounds spent, final
  coverage. Surfaced to the progress emitter and the audit log.

**Critical reconciliation (integration risk, see Risks):** `skillTracker` keys by
**agentName** (dispatcher names: `injection-vuln`, `injection-exploit`, ...), while the
existing `RECOMMENDED` map keys by **promptTemplate name** (`vuln-injection`,
`exploit-injection`, ...). The coverage policy must key by **agentName** and the
prompt footer continues keying by promptName; a single `agentName <-> promptName` map
(already implied by the dispatcher + AGENTS registry) reconciles them. Build this map
explicitly so coverage criteria and tracked usage line up.

**Insertion anchors (from the seam map):**
- Policy + evaluator: `services/prompt-manager/skill-recommendations.ts:26`.
- Coverage read point: `job/pipeline.ts:93` (agent success) / `:96` (failure).
- Continuation wrapper: around `ai/claude-executor/prompt-runner.ts:109-114`
  (`processMessageStream` is re-callable; `runClaudePrompt` is single-pass today).
- Hard-fail bridge to retry: `services/agent-execution/post-execution.ts:180-209`
  (`validateDeliverable`).
- Optional recon fan-out: `temporal/workflows/phases/vuln-exploit.ts:183` / new activity.
- Footer assembly: `services/prompt-manager/loader.ts:109`.
- Tool_use capture (do not touch, just read): `ai/message-handlers/dispatch.ts:83`.

## Decisions Made For You (override in /refine)

- **Default mechanism = coverage gate, not planner fan-out (T6).** Alternative: fan-out
  recon by default. Change this if you'd rather guarantee recon breadth structurally and
  accept the higher token cost.
- **`maxCoverageRounds = 2` (T8).** Alternative: 1 (cheaper, less thorough) or 3 (more
  thorough, costlier). Change this if cost ceilings are tighter/looser than assumed.
- **Recon floor = 6 of the recon candidate set (T8).** Alternative: a required *subset*
  (e.g. naabu+nmap+httpx+katana+nuclei must always run). Change this if certain tools
  are mandatory rather than "any 6."
- **Skips allowed with a one-line justification (T5).** Alternative: forbid skips of any
  candidate (maximally thorough, more false effort on inapplicable tools). Change this
  if you want zero-skip runs.
- **Artifacts live in the aegis repo (`research/`, later `tasks/`).** Alternative: keep
  them in the skill-issue session dir. Chosen because the build target is aegis.

## Key Findings

### F1: LLM agents do not explore broadly without explicit intervention
**Finding:** Multiple 2025-26 results converge: agents under-explore by default and need
strategy scaffolding or forced structure to broaden behavior.
**Evidence:** Strategy-Guided Exploration and the meta-RL exploration work explicitly
frame "LLM agents do not robustly engage in exploration without substantial
interventions" (R2). Matches aegis's single-tool symptom.
**Implications:** Prompt pressure alone (already deployed) is predictably weak; an
external criterion + loop is needed -- justifies T1/T3.

### F2: The Agent SDK query is one-shot; continuation = a second query
**Finding:** Each agent run is one `query()`; the generator ends on the `result`
message and exposes no resume.
**Evidence:** Seam map of `stream-processor.ts:71/115-126`; `maxTurns: 10_000`;
`runClaudePrompt` single-pass; watchdog can only break the loop.
**Implications:** "Keep going" must be a wrapper firing a follow-up query (T3), seeded
with prior context; cannot be done inside the running stream.

### F3: Breadth has a measured cost; bound it
**Finding:** A comprehension-vs-efficiency trade-off is documented; high performers use
targeted search + early stopping and cap rollouts once paths converge.
**Evidence:** MAXS trajectory-convergence + ToolChain* A* cost pruning (R4).
**Implications:** The gate must be bounded (rounds, budget, rate limits) and target the
*applicable* subset, not all tools -- justifies T5/T8.

### F4: aegis already has every hook the loop needs
**Finding:** Live per-agent tool usage (`skillTracker`), a turn-level watchdog, a
post-execution validator -> Temporal retry path, and a per-agent tool-scope map all
exist.
**Evidence:** Seam map: `skill-tracker.ts:70-96`, `dispatch.ts:83`, `watchdog.ts`,
`post-execution.ts:180-209`, `skill-recommendations.ts:26-39`, `pipeline.ts:93/96`.
**Implications:** The design is mostly *wiring existing parts*, not new infrastructure;
keeps the build small and low-risk.

### F5: Prior-art pentest swarms fan out specialists/tools and run an eval suite
**Finding:** PentestGPT, xOffense, PentAGI, Pentest-Swarm-AI orchestrate specialist
sub-agents (planner/recon/exploit/report) with ReAct; XBOW's 104-challenge suite is the
de-facto coverage/skill benchmark (PentestGPT 86.5%).
**Evidence:** R1, R5.
**Implications:** Per-tool fan-out is established (supports optional T6); a canary/eval
harness is standard practice (supports T7).

## References

### R1: Multi-Agent Penetration Testing AI for the Web / AI Pentesting Agents 2026
**Source:** https://arxiv.org/html/2508.20816v1 ; https://appsecsanta.com/research/ai-pentesting-agents-2026
**Takeaway:** 39+ AI pentest tools across 6 architecture patterns; XBOW's 104-challenge
suite is the standard eval and PentestGPT scores 86.5% on it. Orchestration layers assign
specialized agents to recon/scan/exploit -- the multi-specialist shape aegis already uses.

### R2: Expanding LLM Agent Boundaries with Strategy-Guided Exploration; Meta-RL exploration
**Source:** https://arxiv.org/abs/2603.02045 ; https://arxiv.org/pdf/2512.16848
**Takeaway:** LLM agents under-explore by default; explicit natural-language strategy
generation (or RL-induced exploration) is required to broaden action selection. Direct
support for an explicit coverage criterion + scaffolding.

### R3: Anthropic -- Building Effective Agents
**Source:** https://www.anthropic.com/research/building-effective-agents
**Takeaway:** Evaluator-optimizer (generate -> evaluate against clear criteria -> loop)
and orchestrator-workers (decompose -> delegate -> synthesize) are the two patterns that
fit "broaden coverage." Evaluator-optimizer is the chosen default; orchestrator-workers
is the optional recon fan-out.

### R4: MAXS (Meta-Adaptive Exploration) ; ToolChain*
**Source:** https://arxiv.org/pdf/2601.09259 ; https://arxiv.org/pdf/2310.13227
**Takeaway:** Estimate tool-usage advantage and converge/prune to control cost; there is a
real exhaustiveness-vs-efficiency trade-off. Justifies bounding breadth (rounds, budget,
applicable subset).

### R5: Strix / CAI / Pentest-Swarm-AI / xOffense
**Source:** https://github.com/aliasrobotics/CAI ; https://github.com/Armur-Ai/Pentest-Swarm-AI ; https://arxiv.org/html/2509.13021
**Takeaway:** Production-ish agentic security tools run a swarm of specialists with
ReAct, execute real tools in sandboxes, and confirm via actual exploitation -- validating
both per-tool fan-out and observed-tool-usage as the success signal.

## Discarded Approaches

- **Heavier prompt pressure only** -- same lever that already failed (the recon scar
  tissue). Kept as a complementary scaffold, never the primary mechanism.
- **Full Temporal retry on low coverage** -- discards progress, repeats single-tool
  behavior, burns budget. Reserved strictly as the last-resort net for hard-required
  shortfalls.
- **Force every candidate tool to run** -- violates the no-spray rule and no-DoS budget;
  produces noise on inapplicable tools.
- **Semantic / description rewrites as the fix** -- descriptions already grade B with no
  collisions; not the cause. (The minor "Use when" gap is still closed via skill-issue in
  T7, but it is not the mechanism.)

## Risks & Open Threads

- [ ] **agentName vs promptName key mismatch** -- coverage policy keys on agentName,
  footer on promptName. Must build an explicit reconciliation map (Architecture). Highest
  integration risk; verify first in Phase 1.
- [ ] **Justify-to-escape** -- agent could mark every tool "inapplicable" to clear the
  gate. Mitigation: `required` tools cannot be skipped; justifications must be specific
  and are logged for the canary to audit.
- [ ] **Continuation context loss** -- a large prior `result` may not fit cleanly into
  the follow-up. Mitigation: seed with a compact missing-tool list + pointer to the
  on-disk deliverables the agent already reads, not the full transcript.
- [ ] **Cost inflation from extra rounds** -- bounded by `maxCoverageRounds`, per-phase
  budget, and the existing spending-cap safeguard; measured by the canary's token report.
- [x] **Does the SDK support resume?** -- Resolved: no (F2); use a second query.
- [x] **Is tool usage observable per agent at finish?** -- Resolved: yes,
  `skillTracker.skillsFor(agent)` is live (F4).

## Build Plan

Dependency-ordered; phases 1-2 are independent and can run in parallel.

- **Phase 1 -- Coverage policy + evaluator (foundation, no behavior change).**
  `COVERAGE_POLICY` map beside `RECOMMENDED`; the `agentName<->promptName` reconciliation
  map; `evaluateCoverage()` over `skillTracker`; unit tests. Resolves the key-mismatch
  risk first.
- **Phase 2 -- Prompt breadth scaffolding (cheap, immediate win).** Upgrade
  `recommendedSkillsSection()` to emit a tool checklist + breadth-before-depth +
  justify-skips; touch the recon/exploit `.txt` templates only where the footer lands.
- **Phase 3 -- Coverage gate + continuation wrapper (the core fix).** Loop wrapper around
  the single-pass executor; `buildCoverageFollowUp()`; bounded rounds; accumulate usage;
  bridge a persistent hard-required shortfall to `validateDeliverable()`.
- **Phase 4 -- Observability + guardrails.** Emit per-phase coverage (ran/missing/
  skipped+why) through the progress emitter; per-phase tool-call/token budget; honor
  per-host rate limits and the spending-cap safeguard.
- **Phase 5 -- Verification + anti-regression.** Canary scan over `.acceptance/avelero`
  asserting recon and per-category coverage via `skillTracker`; runtime discovery
  preflight (skills discovered + binaries on PATH); `skill-issue --fix` + `--json` CI gate.
- **Phase 6 -- Optional planner fan-out (recon only, default off).** Per-tool parallel
  recon sub-runs behind a flag, inserted at the `vuln-exploit.ts:183` seam / a new
  activity.

## Implementation Log

Built via `/readyforlaunch` on 2026-06-03 (8 tasks, 3 groups, worktree-isolated agents).
Landed on `main` and pushed to origin (`1203992`). Acceptance verdict: **YELLOW** — every
static/unit/wiring criterion PASS with evidence; the live end-to-end scan is BLOCKED on local
runtime provisioning (tool binaries + tsx absent locally), to be run in the worker image.

What shipped (all under `apps/worker/`):
- **Coverage module** `services/coverage/` — `CoveragePolicy`/`CoverageResult`, agentName<->
  promptName reconciliation over the `AGENTS` registry with a load-time drift assertion,
  `COVERAGE_POLICY` (candidates derived from the now-exported `RECOMMENDED`), `evaluateCoverage`,
  `MAX_COVERAGE_ROUNDS`. 21 unit tests.
- **Coverage gate + continuation** `services/agent-execution/coverage-loop.ts` + `service.ts`
  step-5 wrap + dormant hard-miss->OUTPUT_VALIDATION_FAILED bridge in `post-execution.ts`.
- **Breadth footer** upgraded `recommendedSkillsSection()` to a TodoWrite checklist +
  breadth-before-depth + justify-every-skip.
- **Observability** additive `coverage` field on the progress snapshot.
- **Discovery preflight** `services/preflight/tooling-discovery.ts` (+ `skill-catalog.ts`,
  `TOOLING_MISSING`): skills-discovered + binaries-on-PATH, hard-fail in image / warn in dev.
- **Canary** unit canary + guarded local-scan harness `scripts/coverage-canary.ts`.
- **Hygiene/CI** first repo GitHub workflow runs skill-issue; all 31 SKILL.md already carried
  "Use when" triggers (0 edits). **Vitest** introduced as the worker test runner (62 tests).

Deviations from the spec, with rationale:
- **T8 `required` defaulted to `[]`** for every agent (not "exploit category tool required").
  Each exploit category has several valid tools, and a false hard-fail burns a retry; breadth
  is driven by `minCount` + continuation, and the hard-fail->retry bridge is wired but dormant
  (operators opt in by promoting a tool to `required`).
- **002 sequenced after 001** (not parallel as the Build Plan suggested): deriving policy
  candidates from `RECOMMENDED` required exporting it from `skill-recommendations.ts`, the same
  file 002 edits — sequencing avoids a worktree merge conflict.
- **Fan-out seam corrected:** the spec's `vuln-exploit.ts:183` is the *exploit* phase; recon
  actually dispatches at `workflows/index.ts`. Implemented there behind `AEGIS_RECON_FANOUT`
  (default off, flag-off path byte-identical, 8 tests). The fan-out ON-path is **scaffold only**
  and deliberately descoped: a correct version additionally needs per-tool prompt scoping and a
  synthesis merge of the N per-tool recon deliverables — non-trivial, left as a documented
  follow-up.
- **Environment:** the global `WorktreeCreate` hook was pointed at an observer-only `ledger.sh`
  that returned no path, so Agent worktree isolation failed; rewired to a robust creator that
  handles both payload shapes, writes the same ledger, and no-ops on unknown shapes (original
  settings backed up).

Open follow-ups: run the live canary in the provisioned worker image to clear the BLOCKED
criterion; finish or remove the recon fan-out ON-path; (optional) tune thresholds in the policy
map. Acceptance artifacts: `.claude/acceptance/aegis-broaden-tool-coverage/report.md`.
