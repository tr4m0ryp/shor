---
name: trivy
description: "[static-analysis] All-in-one scanner over the connected repo: dependency CVEs across MANY ecosystems (npm, NuGet/.NET, Maven, Go, pip, RubyGems…), plus IaC/Dockerfile/Kubernetes misconfig and a filesystem secret sweep. Reach for it in pre-recon/vuln-analysis for SCA on stacks osv-scanner under-covers and for deeper infra-misconfig than generic SAST."
---

# trivy — SCA + IaC misconfig + secrets (all-in-one)

Aqua's `trivy` (pure-Go). One pass over the checked-out source produces three
read-only views: **vulnerabilities** (SCA against its CVE DB), **misconfigurations**
(Dockerfile, docker-compose, Kubernetes, Terraform, Helm — built-in policies), and
**secrets** (regex/entropy). Read-only, no traffic to the target → **pre-recon /
vuln-analysis**. Complements the focused tools: it covers .NET/NuGet SCA that a
lockfile-only osv-scanner run misses, and finds far more infra misconfig than
semgrep's generic rules.

## When to reach for it
- SCA on a multi-stack repo — especially **.NET/NuGet**, where osv-scanner needs a
  `packages.lock.json` that ASP.NET projects often don't commit; trivy reads
  `*.csproj` / `packages.config` / `*.deps.json` as well.
- IaC/container misconfig sweep (Dockerfile hardening, K8s securityContext, compose).
- A second secret-scan opinion alongside gitleaks/trufflehog.

## Key flags
- `trivy fs <path>` scan a filesystem/repo (the mode for source uploads).
- `--scanners vuln,misconfig,secret` choose the views (default vuln+secret+misconfig
  for `fs`); narrow it to cut runtime.
- `--format json -o out.json` structured output (also `sarif`, `cyclonedx` SBOM).
- `--severity CRITICAL,HIGH,MEDIUM` filter; `--exit-code 0` keep the pipeline going.
- `--cache-dir /tmp/.cache/trivy` writable cache (HOME=/tmp at runtime).
- `--skip-db-update` reuse a cached DB when egress is constrained (may be stale).

## Safe invocation
```bash
# Vulns + misconfig + secrets over the repo, JSON out, never fail the run
trivy fs /path/to/repo \
  --scanners vuln,misconfig,secret \
  --severity CRITICAL,HIGH,MEDIUM \
  --format json -o trivy.json \
  --cache-dir /tmp/.cache/trivy --exit-code 0
```
> First run downloads the vuln DB from ghcr.io (cached afterwards). Confirm the
> CLI surface with `trivy --help`; subcommands shifted across major versions.

## Evidence to capture
- SCA: package, installed version, CVE/GHSA id, severity, **fixed version**, manifest.
- Misconfig: policy id (e.g. `AVD-DS-0002`), file, line, the insecure setting.
- Secrets: rule id, file, line, **redacted** match.
- Cross-check SCA against osv-scanner (different DBs) and rank by reachability from
  an in-scope entry point; cross-check secrets against gitleaks/trufflehog.

## Scope & rate caveats
- Source/repo only — **no target traffic**. The only egress is the DB pull from
  ghcr.io (tool infra, not the target); honor it under the run's egress policy.
- A vulnerable dep present ≠ exploitable here — note reachability, don't auto-promote.
- ALWAYS keep secrets redacted in findings and logs; secret-hygiene is enforced.
- Scan only the in-scope checked-out repo.
