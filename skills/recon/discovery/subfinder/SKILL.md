---
name: subfinder
description: "[recon] Passive subdomain enumeration for a root domain via public sources (no direct traffic to the target). Reach for it first to expand the host attack surface before live probing."
---

# subfinder — passive subdomain discovery

ProjectDiscovery's `subfinder` (pure-Go). Aggregates subdomains from passive
sources (certificate transparency, passive DNS, search APIs). Passive by design:
it queries third-party data sources, not the target itself.

## When to reach for it
- First recon step for a registered apex domain in scope.
- To widen the host list before dnsx (resolve) → httpx (probe live).

## Key flags
- `-d <domain>` target apex (repeatable) or `-dL <file>` list of domains.
- `-all` use all sources (slower, broader); default is the fast curated set.
- `-recursive` recurse into discovered subdomains.
- `-silent` only print domains (clean for piping).
- `-oJ -o out.json` JSON output; `-rl <n>` rate limit to source APIs.
- `-nW` show only resolvable hosts (when combined with resolution).

## Safe invocation
```bash
# Enumerate in-scope apex, pipe straight into resolve+probe
subfinder -d target.example.com -all -silent \
  | dnsx -silent -a -resp \
  | httpx -silent -sc -title
```

## Evidence to capture
- The raw subdomain list (provenance for the attack-surface map).
- Note which hosts resolve and which serve HTTP (downstream from dnsx/httpx).

## Scope & rate caveats
- Enumerate ONLY apex domains explicitly in scope. Subdomains discovered may
  themselves be out of scope (shared infra, third-party SaaS) — validate each
  against the Rules of Engagement before probing or attacking it.
- Passive, so low target impact, but several sources need API keys; missing keys
  silently reduce coverage, not an error.
- Treat results as candidates, not confirmed live hosts — always resolve+probe.
