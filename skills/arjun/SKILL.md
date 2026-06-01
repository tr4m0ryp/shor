---
name: arjun
description: "[recon] HTTP parameter discovery — find hidden/unlinked query, body, JSON, and header params an endpoint silently accepts. Reach for it before injection/XSS testing to expand the input surface of an endpoint."
---

# arjun — hidden parameter discovery

`arjun` (Python, from the shared venv). Probes an endpoint with candidate
parameter names and detects which ones change the response — revealing inputs
not present in the HTML/JS. Hidden params are prime injection/IDOR vectors.

## When to reach for it
- After katana/gau give you endpoints, to enumerate the params each one accepts.
- Right before sqlmap/dalfox/SSTImap — to hand them a complete input list.
- When an endpoint "does nothing" but probably hides debug/admin params.

## Key flags
- `-u <url>` single endpoint; `-i <file>` list of URLs (e.g. from katana).
- `-m GET|POST|JSON|XML` method/body type to fuzz params in.
- `-w <wordlist>` custom param names (ships with a default set).
- `-d <sec>` delay between requests; `-t <n>` threads/concurrency.
- `-c <n>` chunk size (params tested per request); `--headers` send auth headers.
- `-oJ out.json` / `-oT out.txt` output; `--stable` slower but fewer false positives.

## Safe invocation
```bash
# Mine GET params for one in-scope endpoint, throttled, JSON out
arjun -u https://target.example.com/api/item -m GET \
  -d 1 -t 5 --stable -oJ arjun.json
```

## Evidence to capture
- Confirmed accepted parameter names per endpoint (+ method/body type).
- Suspicious params (`debug`, `admin`, `redirect`, `id`, `file`) → flag for injection/SSRF/IDOR.

## Scope & rate caveats
- Run ONLY against in-scope endpoints. Arjun sends many requests per endpoint —
  use `-d`/`-t` to throttle and honor per-host no-DoS limits.
- It only finds that a param is *accepted*; it does not confirm a vuln. Confirm
  with the relevant exploit tool before reporting.
