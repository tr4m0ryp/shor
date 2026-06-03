---
name: gau
description: "[recon] getallurls — pull known historical URLs for a domain from Wayback, Common Crawl, OTX, URLScan (passive). Reach for it to recover old/forgotten endpoints and parameterized URLs without touching the target."
---

# gau — historical URL harvesting

`gau` (getallurls, Go). Queries public archives for URLs ever seen for a domain.
Passive: it talks to archive providers, not the target. Pairs with `waybackurls`
(overlapping but complementary sources) and with `katana` (live crawl).

## When to reach for it
- To surface legacy/undocumented endpoints and parameter names from history.
- To seed ffuf/arjun and nuclei with real, previously-live URLs.
- Early recon, before generating live traffic.

## Key flags
- `gau <domain>` or domains on stdin; `--subs` include subdomains.
- `--providers wayback,commoncrawl,otx,urlscan` choose sources.
- `--threads <n>`; `--json` structured output.
- `--fc 404` / `--mc 200` filter by status (gau can verify); `--blacklist png,jpg,css` drop noise.
- `--from`/`--to YYYYMM` time-bound the archive query.

## Safe invocation
```bash
# Historical URLs incl. subdomains, drop static noise, keep ones with params
gau --subs --blacklist png,jpg,gif,css,woff target.example.com \
  | grep '?' | sort -u > gau-params.txt
```

## Evidence to capture
- De-duplicated historical URL list, especially URLs carrying query parameters.
- Old endpoints absent from the live crawl (often less-maintained = higher risk).

## Scope & rate caveats
- Output is *historical* — many URLs are dead or moved. Re-probe with httpx and
  re-validate scope before treating any as a live target.
- Passive on the target, but archive providers rate-limit; keep threads modest.
- Filter aggressively; raw archive dumps are huge and mostly static assets.
