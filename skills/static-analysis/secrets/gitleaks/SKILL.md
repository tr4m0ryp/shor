---
name: gitleaks
description: "[static-analysis] Scan a repo's files and full git history for hardcoded secrets (keys, tokens, credentials). Reach for it in vuln-analysis to find committed secrets, including ones removed from HEAD but live in history."
---

# gitleaks — secret scanning (repo + history)

`gitleaks` (pure-Go). Detects hardcoded secrets via regex + entropy across the
working tree and the entire git history. Read-only, no target traffic →
**vuln-analysis** phase. Catches secrets that were "deleted" but remain in old
commits.

## When to reach for it
- Whitebox secret sweep of the connected repo.
- To check git history (not just HEAD) for leaked keys/tokens/passwords.

## Pick the mode by what's on disk (IMPORTANT)
- **`gitleaks dir <path>`** scans the **working tree** — it ALWAYS works,
  including uploads that have **no `.git`**. Make this your default.
- **`gitleaks git <repo>`** scans **commit history** — only meaningful when a
  `.git` directory is present. It finds NOTHING on a `.git`-less upload, so do
  NOT fall back to "skip secret scanning" when history is empty — run `dir` mode.
- Most uploaded codebases arrive WITHOUT history → `dir` mode is the one that
  actually scans the source. Run `git` mode ADDITIONALLY only if `.git` exists.

## Key flags
- `gitleaks dir <path>` (working tree) / `gitleaks git <repo>` (history).
  (Older syntax: `detect --source`.)
- `--report-format json --report-path out.json` structured output (also `sarif`).
- `--log-opts "--all"` scan all refs (history mode); `--no-git` treat as plain files.
- `-c gitleaks.toml` custom rules/allowlist; `--redact` redact secrets in output.
- `--exit-code 0` to keep the pipeline going when leaks are found.

## Safe invocation
```bash
# Always scan the working tree (works with or without .git), redacted JSON:
gitleaks dir /path/to/repo --report-format json \
  --report-path gitleaks.json --redact --exit-code 0
# If a .git dir is present, ALSO sweep history for removed-but-committed secrets:
[ -d /path/to/repo/.git ] && gitleaks git /path/to/repo --report-format json \
  --report-path gitleaks-history.json --redact --exit-code 0
```
> Verify subcommands with `gitleaks --help`; v8 uses `git`/`dir`, older uses `detect`.

## Evidence to capture
- Per-leak: rule id, file, line, commit, author, and the **redacted** match.
- Map to CWE-798 (hardcoded credentials); cross-check trufflehog for live-verified hits.

## Scope & rate caveats
- Source/history only — no target rate or egress concern.
- ALWAYS `--redact` (or redact before storing); never write raw secrets into a
  finding record or log — secret-hygiene is enforced.
- Expect false positives (test fixtures, examples); confirm a secret is real and
  in-scope before treating it as a confirmed finding.
