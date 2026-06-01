---
name: semgrep
description: "[static-analysis] Static code analysis (SAST) over the connected repo — taint/pattern rules per vuln category, no live traffic. Reach for it in vuln-analysis to locate vulnerable code at file:line that DAST then confirms."
---

# semgrep — static analysis (SAST)

`semgrep` (Python, shared venv). Runs pattern/taint rules against source in the
checked-out repo. Read-only, no network traffic to the target — it belongs in the
**vuln-analysis** phase. Its output gives the `file:line` that downstream live
exploitation aims at and that the finding's `vulnerable_code_location` needs.

## When to reach for it
- Whitebox pass over the connected repo for injection, XSS sinks, SSRF, authz
  gaps, secrets-in-code, and language-specific bug classes.
- To produce precise code locations that anchor each finding's fingerprint.

## Key flags
- `--config p/ci|p/owasp-top-ten|<rule-dir>|auto` ruleset (per-category packs preferred).
- `--json -o out.json` structured output (SARIF: `--sarif`).
- `--severity ERROR|WARNING`; `--include`/`--exclude` paths; `--metrics=off`.
- `--max-target-bytes`, `--timeout <s>` for big repos.
- `--baseline-commit <sha>` report only new findings vs a prior commit (diff scans).

## Safe invocation
```bash
# Category ruleset over the repo, metrics off, JSON out
semgrep --config p/owasp-top-ten --severity ERROR --metrics=off \
  --json -o semgrep.json /path/to/repo
```

## Evidence to capture
- Per-finding `check_id`, `path`, `start.line`, the matched code snippet, message.
- The taint source→sink path: feeds the exploit agent a concrete hypothesis and
  populates `vulnerable_code_location` + `missing_defense`.

## Scope & rate caveats
- Operates on source, not the live target — no rate/egress concern, but it is
  **static**: a match is a candidate, confirmed only by a live PoC (XBOW pattern).
- Run only on the in-scope checked-out codebase; do not scan unrelated paths.
- Pin the ruleset version per run so findings are stable and diffable across scans.
