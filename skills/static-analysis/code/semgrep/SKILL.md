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

## Target the BACKEND language, not just `auto` (IMPORTANT)
`--config auto` over-weights config/YAML/Docker rules and routinely returns only
**infrastructure** findings while missing the application backend entirely — a
C#/.NET, Java, Go, or Python server can come back with zero app-level hits. Always
ALSO run the language pack for the stack you found in the architecture phase:
- `p/csharp` (.NET / ASP.NET), `p/java`, `p/golang`, `p/python`, `p/javascript`,
  `p/typescript`, `p/php`, `p/ruby`.
- Plus the category packs: `p/owasp-top-ten`, `p/sql-injection`, `p/xss`,
  `p/command-injection`, `p/secrets`, and `p/nosql` (e.g. a MongoDB data layer).
Stack the configs in one run (repeat `--config`). If a language pack returns
nothing on a backend you KNOW has handlers, treat that as a tooling gap, not a
clean bill — note it and lean on the Task-agent review.

## Key flags
- `--config p/owasp-top-ten|p/csharp|<rule-dir>|auto` — repeat to stack rulesets.
- `--json -o out.json` structured output (SARIF: `--sarif`).
- `--severity ERROR|WARNING`; `--include '*.cs'` to focus the backend; `--metrics=off`.
- `--max-target-bytes`, `--timeout <s>` for big repos.
- `--baseline-commit <sha>` report only new findings vs a prior commit (diff scans).

## Safe invocation
```bash
# Language pack + OWASP + NoSQL stacked over the repo (e.g. an ASP.NET + Mongo app)
semgrep --config p/csharp --config p/owasp-top-ten --config p/nosql \
  --severity ERROR --metrics=off --json -o semgrep.json /path/to/repo
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
