---
name: ssrfmap
description: "[exploit] Automate SSRF exploitation from a captured request + the injectable parameter — internal probing, cloud-metadata reads, port scan modules. Reach for it once an SSRF sink is identified to reach a minimal-impact PoC."
---

# SSRFmap — SSRF exploitation framework

`SSRFmap` (Python; pinned git clone, run in place from `/opt/aegis/tools/SSRFmap`,
e.g. `python ssrfmap.py`). Takes a raw request file plus the SSRF-vulnerable
parameter and runs modules (internal-host probe, cloud metadata, port scan, etc.).
**Live → exploitation phase.** Honor the SSRF PoC ceiling: stop at first
boundary-crossing proof, no credential retrieval.

## When to reach for it
- Recon/semgrep identified a parameter whose value the server fetches (webhook,
  url=, image proxy, importer) and you need to confirm internal reach minimally.

## Key flags / modes
- `-r <req.txt>` raw HTTP request file (capture via curl/Burp/Playwright).
- `-p <param>` the injectable parameter to inject SSRF payloads into.
- `-m <modules>` comma-separated: `readfiles`, `portscan`, `aws`, `gce`, `azure`,
  `digitalocean`, `redis`, etc. Choose the **minimal** module for the hypothesis.
- `-l <port>` / `--lhost`/`--lport` for OOB/listener-based confirmation.
- `--level <n>` payload aggressiveness (keep low).

## Safe invocation
```bash
# Probe AWS metadata reachability via the captured request's `url` param
ssrfmap -r req.txt -p url -m aws
# Internal loopback banner check: ssrfmap -r req.txt -p url -m portscan (bounded)
```
> Capture `req.txt` first, e.g.: `curl -sS -o /dev/null --trace-ascii req.txt ...`
> or save the Playwright/Burp request. Confirm modules with `ssrfmap --help`.

## Evidence to capture
- The injected request, the SSRF type, and ONE Level-3 proof: an internal service
  banner, a first-level cloud-metadata directory listing, or an OOB callback whose
  source IP matches target egress. Map to CWE-918.

## Scope & rate caveats
- PoC CEILING (non-negotiable): stop at the first boundary-crossing proof. Do NOT
  fetch IAM/identity credentials, enumerate beyond a directory listing, full-port-
  sweep internal ranges, or weaponize `gopher://`/`redis` to mutate state.
- Read-only requests only; ≤3 internal targets to distinguish "blocked" vs "no vuln".
- Target ONLY the in-scope sink; pinned commit keeps runs reproducible. Redact any
  captured secret.
