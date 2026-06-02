---
name: katana
description: "[recon] Crawl a live web app to enumerate URLs, endpoints, JS-referenced paths, and forms. Reach for it to build the in-app URL/endpoint inventory that feeds param discovery, fuzzing, and DAST."
---

# katana — web crawler / endpoint discovery

ProjectDiscovery's `katana` (Go, built `CGO_ENABLED=1`). Crawls a live target and
extracts URLs, parameters, and endpoints — including ones referenced from JS.
This image uses DOM/source crawling (headless browser mode is optional and heavier).

## When to reach for it
- After httpx confirms a live host, to map its actual URL/endpoint surface.
- To extract links, query params, and API paths for arjun/ffuf/nuclei to act on.
- To pull endpoints out of inline and external JavaScript.

## Key flags
- `-u <url>` / `-list <file>` seed targets.
- `-d <n>` crawl depth; `-jc` crawl JS files; `-kf robotstxt,sitemapxml` known files.
- `-fs fqdn` field-scope to the seed host (stay on-target); `-crawl-scope`/`-crawl-out-scope` regex.
- `-rl <n>` rate limit; `-c <n>` concurrency; `-timeout <s>`.
- `-jsonl` structured output; `-f url,qurl` output fields (e.g. only URLs with query params).
- `-headless` browser mode (heavier; needs chromium) — usually unnecessary here.

## Safe invocation
```bash
# Depth-3 crawl incl. JS, scoped to the host, rate-limited, JSONL out
katana -u https://target.example.com -d 3 -jc -fs fqdn \
  -rl 15 -c 10 -jsonl -o katana.jsonl
```

## Evidence to capture
- The endpoint/URL inventory (esp. URLs *with* query params → injection candidates).
- New paths not in the recon map; JS-sourced API routes.

## Scope & rate caveats
- Crawl ONLY the in-scope host; set `-fs fqdn` (or scope regex) so links to
  third-party domains are not followed and hit.
- A crawler issues many requests and may trigger state-changing GET endpoints —
  keep `-rl` modest; honor per-host limits; stop on 429.
- Authenticated crawling: drive auth separately, then crawl with the session.
