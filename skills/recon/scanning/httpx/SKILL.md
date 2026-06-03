---
name: httpx
description: "[recon] Probe a list of hosts/URLs for live HTTP(S) services and fingerprint them (status, title, tech, TLS). Reach for it to turn raw subdomains/ports into a confirmed live-web attack surface."
---

# httpx — fast HTTP probe & fingerprint

ProjectDiscovery's `httpx` (pure-Go). Takes a list of hosts/URLs on stdin or
`-l` and reports which are live, with metadata. This is the recon step that
converts subfinder/dnsx/naabu output into confirmed web endpoints.

## When to reach for it
- After subdomain/DNS/port discovery, to find which hosts actually serve HTTP(S).
- To fingerprint tech stack, status codes, titles, redirects across many hosts fast.
- To snapshot the live surface before katana/nuclei/ffuf.

## Key flags
- `-l <file>` / stdin — input list of hosts or URLs.
- `-sc` status-code, `-title`, `-td` tech-detect (Wappalyzer), `-server` Server header.
- `-cl` content-length, `-location` redirect target, `-ip`, `-cname`.
- `-json` structured output (one JSON object per line) — prefer for parsing.
- `-rl <n>` rate limit (requests/sec); `-threads <n>` concurrency.
- `-mc 200,302` match status codes; `-fc 404` filter codes.
- `-follow-redirects` (off by default).

## Safe invocation
```bash
# Probe discovered hosts, emit JSON, rate-limited, in-scope only
httpx -l hosts.txt -json -sc -title -td -server -ip \
  -rl 20 -threads 25 -timeout 10 -o httpx.jsonl
```
Single host: `echo target.example.com | httpx -json -td -sc -title`.

## Evidence to capture
- The JSONL: per-host `url`, `status_code`, `title`, `tech`, `webserver`, `a`/`cname`.
- Live-host shortlist feeds katana (crawl), nuclei (template scan), ffuf (content).

## Scope & rate caveats
- Probe ONLY hosts inside the validated Rules of Engagement. Do not let subdomain
  wildcards pull in out-of-scope third-party hosts.
- Keep `-rl` modest (≤ a few dozen/sec per host); httpx fans out wide by default.
  Honor per-host rate limits; stop on repeated timeouts/429.
- This is a probe, not a scanner — it should not send attack payloads.
