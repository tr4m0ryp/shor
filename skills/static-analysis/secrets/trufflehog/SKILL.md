---
name: trufflehog
description: "[static-analysis] Find secrets in a repo/history/filesystem and LIVE-VERIFY them against the issuing provider. Reach for it in vuln-analysis when you need to separate truly-active leaked credentials from dead noise."
---

# trufflehog — secret detection with live verification

`trufflehog` (pure-Go). Like gitleaks it finds secrets across repo/history/files,
but its differentiator is **verification**: for many detector types it calls the
provider's API to confirm the credential is still active. Read-only on the repo →
**vuln-analysis** phase. Use it to prioritize gitleaks hits by "is it live".

## When to reach for it
- After/with gitleaks, to confirm which detected secrets are actually live.
- Deep secret sweep across git history or a directory of artifacts.

## Pick the mode by what's on disk (IMPORTANT)
- **`trufflehog filesystem <path>`** scans files directly — works on uploads
  with **no `.git`**. Make this your default.
- **`trufflehog git file:///<repo>`** scans history — only when `.git` exists.
  On a `.git`-less upload it finds nothing; use `filesystem` mode instead of
  concluding "no secrets".

## Key flags
- `trufflehog filesystem <path>` (files) or `trufflehog git file:///path/to/repo` (history).
- `--only-verified` report only credentials confirmed live (cuts false positives).
- `--json` structured output (one JSON object per finding).
- `--results=verified,unknown` control which verification states to emit.
- `--since-commit <sha>` / `--branch <ref>` bound the scan for diffs.

## Safe invocation
```bash
# Default: filesystem scan (works with or without .git), verified-only, JSON out
trufflehog filesystem /path/to/repo --only-verified --json > trufflehog.jsonl
# If .git exists, ALSO sweep history:
[ -d /path/to/repo/.git ] && trufflehog git file:///path/to/repo \
  --only-verified --json >> trufflehog.jsonl
```

## Evidence to capture
- Per finding: detector type, file/commit, verification status, **redacted** secret.
- A `verified: true` credential is a high-severity confirmed finding (CWE-798);
  record the redacted value + where it grants access — never the raw secret.

## Scope & rate caveats
- **Verification makes live outbound calls to third-party providers** (GitHub,
  AWS, etc.). That egress must be allowed and in policy; if egress is locked down,
  run without verification and note the limitation rather than assuming.
- ALWAYS store secrets redacted; secret-hygiene is enforced in logs and findings.
- Scan only the in-scope repo/artifacts; do not exfiltrate found secrets.
