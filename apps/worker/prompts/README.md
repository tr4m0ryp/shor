# prompts/ — category system prompts (ported from storron)

Ported from `storron/apps/worker/prompts/` (kept rich and detailed), with three
deliberate changes:

1. **Dropped the onion variant** (`pre-recon-onion.txt`) and its template
   selection. No Tor/onion references remain (clearnet only).
2. **Added a `<tool_skills>` section** to each category prompt that references
   the relevant per-tool skills by name (see `../skills/`, ADR-035). Placed
   right after each prompt's existing `<cli_tools>` block.
3. **Inverted the attack-surface prompt** (`attack-surface.txt`): its
   `<claude_code_prompt_template>` changed from an *attack/reproduce* template
   ("reproduce the reported behavior at `<url>`") to a **remediation/fix**
   template that targets the connected repository and resolves the issue at its
   root cause, built from each finding's `vulnerable_code_location` (file:line)
   and `missing_defense` (ADR-010, LAUNCH-SPEC §6.2, research/output-schema.md
   §3). The JSON field name `claude_code_prompt` is unchanged for dashboard
   compatibility — only the template content changed.

Ported files: `pre-recon-code`, `recon`, `vuln-{injection,xss,auth,authz,ssrf}`,
`exploit-{injection,xss,auth,authz,ssrf}`, `attack-surface`, `report-executive`,
plus the `shared/_*.txt` includes. The `@include(...)` mechanism from the
prompt-manager is preserved (`shared/_vuln-scope.txt`, `_exploit-scope.txt`,
`_target.txt`, `_rules.txt`).

`<tool_skills>` is present on every category agent prompt (recon, pre-recon, and
all `vuln-*` / `exploit-*`). It is intentionally omitted from `attack-surface`
(pure synthesis) and `report-executive` (reporting) — neither runs offensive
tools.

## `finalize/` — post-scan finalization prompts (recovered SINAS layer)

`finalize/{findings-improver,attack-surface,report}.txt` are the **full system
prompts for the finalize layer** that runs after the engine pipeline
(`job/cli-finalization.ts`): findings rewrite → attack-surface synthesis →
executive report, over a single Claude CLI session. They are the recovered
SINAS Opus/Sonnet v2 prompts (severity-complete, no top-N cap, with a worked
formatting example), restored after the SINAS backend was retired. Each stage
appends an explicit JSON-output contract at call time because the CLI path has
no structured-output schema enforcement. These are distinct from the
`attack-surface.txt` / `report-executive.txt` at the root, which are the
per-scan **engine pipeline** agents.
