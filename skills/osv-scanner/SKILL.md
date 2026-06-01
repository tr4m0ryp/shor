---
name: osv-scanner
description: "[static-analysis] Scan lockfiles/SBOM/dependencies against the OSV database for known-vulnerable package versions. Reach for it in vuln-analysis to surface CVEs in third-party deps with fixed-version guidance."
---

# osv-scanner — dependency vulnerability scanning

Google's `osv-scanner` (pure-Go). Reads lockfiles/SBOMs in the repo and matches
dependency versions against the OSV.dev vulnerability database. Read-only, no
target traffic → **vuln-analysis** phase. This is the software-composition (SCA)
view: vulnerable libraries the app ships.

## When to reach for it
- Whitebox SCA pass over the connected repo's dependency manifests/lockfiles.
- To enumerate known-CVE deps and the version that fixes each.

## Key flags
- `scan source -r <path>` recursively scan a project's lockfiles (newer CLI).
  Older/simple form: `osv-scanner -r <path>` or `--lockfile <file>`.
- `--sbom <file>` scan a CycloneDX/SPDX SBOM.
- `--format json --output out.json` structured output (also `sarif`, `markdown`).
- `--call-analysis` (where supported) to reduce noise to reachable vulns.

## Safe invocation
```bash
# Recursively scan repo lockfiles against OSV, JSON out
osv-scanner scan source -r /path/to/repo --format json --output osv.json
```
> CLI surface shifted between versions; confirm with `osv-scanner --help`.

## Evidence to capture
- Per-vuln: package, installed version, OSV/CVE id, severity, **fixed version**.
- Fixed-version + manifest path makes a clean, actionable remediation prompt.

## Scope & rate caveats
- Manifest/source only — no target rate or egress concern (OSV lookups may use a
  local DB or query osv.dev; honor any provider limits).
- A vulnerable dep present ≠ exploitable in this app; note reachability where the
  tool can, and prefer it over raw version-match when available.
- Scan only the in-scope checked-out repo.
