---
name: git-security-history
description: "[static-analysis] Mine the cloned repo's OWN git history for past security/fix commits and map them to recurring hot files, then fold in dependency-CVE (osv-scanner) and history-secret (gitleaks) signals. Reach for it in pre-recon to seed 'what's been exploited before' — code patched for a vuln once is the highest-yield place to re-examine."
---

# git-security-history — historical-exploit seeding (local, no network)

A small recipe over the **already-cloned repo**. It runs `git log --grep` for
security/CVE/fix patterns, maps the touched files into ranked **hot files**, and
emits `historical_signal.json`. It optionally folds in two signals you may have
ALREADY produced this phase — `osv-scanner` JSON (dependency CVEs) and
`gitleaks` JSON (history secrets) — by READING their report files. Read-only,
**no target traffic, no network egress** → it belongs in the **pre-recon /
vuln-analysis** phase. This is the "history as oracle" view: where has this code
been fixed for security before?

## When to reach for it
- First thing in whitebox pre-recon, to bias discovery toward code with a track
  record of security fixes (auth, parsers, upload, redirect, template render).
- To carry dependency CVEs and any history-leaked-secret files into one compact
  seed the downstream agents read via `{{HISTORICAL_SEED}}`.

## What it runs (all LOCAL)
- `git -C <repo> log --all -i -E --grep="secur|vuln|CVE-|XSS|SQLi|injection|auth bypass|RCE|SSRF|IDOR|sanitiz" --name-only` to find security/fix commits and the files they touched.
- Groups commits by file → `hotFiles[]`, ranked by security-commit count; pulls
  any `CVE-####-####` ids out of the subjects.
- Folds `--osv <osv.json>` (osv-scanner output) → `depCves[]`, and
  `--gitleaks <gitleaks.json>` (gitleaks `--redact` output) → secret-touched
  files added to `hotFiles[]`. Both are **optional and read-only**; this skill
  NEVER invokes those tools or the network itself.

## Safe invocation
`mine.sh` and `assemble.py` ship in THIS skill directory (siblings of this
`SKILL.md`), so they travel with the skill wherever it is discovered. Run the
`mine.sh` next to this file:
```bash
# Mine history + fold any reports already written this phase. python3 required
# (the semgrep venv provides it). Writes the deliverable in place.
skills/static-analysis/history/git-security-history/mine.sh \
  --repo "$REPO_PATH" \
  --out  "$REPO_PATH/.storron/deliverables/historical_signal.json" \
  --osv  "$REPO_PATH/.storron/deliverables/osv.json" \
  --gitleaks "$REPO_PATH/.storron/deliverables/gitleaks.json"
```
`--osv` / `--gitleaks` are optional — omit them (or point at a missing file) and
that signal is simply skipped. Run `osv-scanner`/`gitleaks` via their own skills
first if you want those signals; this recipe only consumes their JSON.

## Output schema (`historical_signal.json`)
```json
{
  "hotFiles": [
    { "file": "src/auth/login.ts",
      "commits": [{ "sha": "abc123", "date": "2024-01-02", "subject": "fix auth bypass" }],
      "cves": ["CVE-2021-1234"] }
  ],
  "depCves": [
    { "package": "lodash", "version": "4.17.20", "id": "CVE-2021-23337",
      "severity": "HIGH", "fixedVersion": "4.17.21" }
  ]
}
```
`cves` and `fixedVersion` are optional. The shape is pinned by the worker
normalizer (`apps/worker/src/services/history-seed`), which re-normalizes it on
read for task 005's `{{HISTORICAL_SEED}}` renderer.

## Evidence to capture
- Per hot file: path, the security/fix commits (sha/date/subject), referenced CVEs.
- Per dep CVE: package, installed version, advisory id, severity, fixed version.
- Treat each as a HYPOTHESIS to re-test live, not a confirmed finding.

## Scope & rate caveats
- History/reports only — **no target rate or network egress**; `osv-scanner`'s
  own egress posture lives in its skill, not here (this recipe never calls it).
- **Redaction is enforced:** commit subjects are scrubbed of secret-shaped tokens
  before they are written; run `gitleaks` with `--redact` so its report carries
  no raw secret either. Never echo a secret value into the deliverable.
- Operate only on the in-scope checked-out repo; a shallow clone limits history
  depth (note it if `git log` is short).
