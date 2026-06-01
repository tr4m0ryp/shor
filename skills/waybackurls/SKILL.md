---
name: waybackurls
description: "[recon] Fetch every URL the Wayback Machine recorded for a domain (passive). Reach for it alongside gau to recover historical endpoints and parameterized URLs without sending traffic to the target."
---

# waybackurls — Wayback Machine URL dump

`waybackurls` (tomnomnom, Go). Pulls all URLs the Internet Archive's Wayback
Machine has for a host. Single-source and minimal by design; run it together with
`gau` (which adds Common Crawl/OTX/URLScan) for fuller coverage.

## When to reach for it
- Quick passive recovery of historical URLs/params for a domain.
- To cross-check / supplement gau output from the Wayback source specifically.

## Key flags
- `waybackurls <domain>` or domains on stdin (no resolution, no probing).
- `--dates` prefix each URL with its archive timestamp.
- `--no-subs` restrict to the exact host (default includes subdomains).
- It is deliberately flag-light; post-process with `sort -u`, `grep`, `unfurl`.

## Safe invocation
```bash
# Wayback URLs for the host, keep parameterized ones, de-dup
waybackurls target.example.com | grep '?' | sort -u > wayback-params.txt
# Combine with gau for broader history:
# cat wayback-params.txt gau-params.txt | sort -u > all-historical.txt
```

## Evidence to capture
- De-duplicated historical URL list (provenance for endpoint/param candidates).
- Parameterized URLs feed arjun (param mining) and ffuf/nuclei (value fuzzing).

## Scope & rate caveats
- Historical only — URLs may be dead or out of scope now. Re-probe with httpx and
  re-validate against the Rules of Engagement before targeting.
- Passive on the target; the Wayback API itself rate-limits large hosts.
