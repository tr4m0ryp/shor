---
name: wafw00f
description: "[recon] Fingerprint whether a target sits behind a WAF/CDN and which product it is. Reach for it before active testing so you know to expect/throttle around filtering and plan bypasses."
---

# wafw00f — WAF/CDN fingerprinting

`wafw00f` (Python, shared venv). Sends a few benign probes and matches the
responses against signatures to identify the Web Application Firewall or CDN in
front of a target. Run it early so downstream agents know filtering is present.

## When to reach for it
- Right after httpx confirms a live host, before injection/XSS/fuzzing.
- When payloads start getting blocked/`403`'d and you suspect a WAF.

## Key flags
- `wafw00f <url>` single target; `-i <file>` list of URLs.
- `-a` test for ALL WAFs even after a match (don't stop at first).
- `-o out.json -f json` structured output; `-f csv` also supported.
- `-p proxy` route through a proxy; `-v`/`-vv` verbosity.
- `-l` list all WAFs it can detect.

## Safe invocation
```bash
# Fingerprint the in-scope host, check all signatures, JSON out
wafw00f https://target.example.com -a -o wafw00f.json -f json
```

## Evidence to capture
- Detected WAF/CDN product name (or "no WAF detected") per host.
- Record it in the attack-surface map; it sets expectations for evasion needs
  (e.g. sqlmap `--tamper`, encoded payloads) and explains blocked requests.

## Scope & rate caveats
- Probe ONLY in-scope hosts. The probes are benign and few, so impact is low.
- Detection is signature-based: a "no WAF" result is not a guarantee of none,
  and a CDN (Cloudflare/Akamai) may be reported where there is no security WAF.
- Knowing the WAF is context, not a finding — do not report it as a vuln.
