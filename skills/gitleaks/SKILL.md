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

## Key flags
- `git -C <repo> ...` then `gitleaks dir <path>` (working tree) or
  `gitleaks git <repo>` (history). (Older syntax: `detect --source`.)
- `--report-format json --report-path out.json` structured output (also `sarif`).
- `--log-opts "--all"` scan all refs; `--no-git` treat as plain files.
- `-c gitleaks.toml` custom rules/allowlist; `--redact` redact secrets in output.
- `--exit-code 0` to keep the pipeline going when leaks are found.

## Safe invocation
```bash
# Scan full history of the checked-out repo, redacted JSON report
gitleaks git /path/to/repo --report-format json \
  --report-path gitleaks.json --redact
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
