---
name: nuclei
description: "[recon/exploit] Template-driven vulnerability & misconfig scanner over live URLs (CVEs, exposures, default creds, takeovers). Reach for it for fast, broad, signature-based coverage once you have a live-host list."
---

# nuclei — templated vulnerability scanning

ProjectDiscovery's `nuclei` (pure-Go). Runs a large community + custom template
library against live targets to flag known CVEs, misconfigurations, exposures,
and default credentials. Breadth-first signal that focuses the deeper, tool- and
agent-specific exploitation.

## When to reach for it
- After httpx, to sweep the live surface for known issues quickly.
- To confirm a version-based CVE lead (target the matching template/tag).
- For exposure checks (open panels, `.git`, config leaks, subdomain takeover).

## Key flags
- `-u <url>` / `-l <file>` targets (use the httpx live list).
- `-t <path>` specific templates/dirs; `-tags cve,exposure`; `-severity critical,high`.
- `-rl <n>` rate limit (global req/sec); `-c <n>` concurrency; `-timeout <s>`.
- `-jsonl -o out.jsonl` structured output (prefer for the findings sink).
- `-etags dos,fuzz` exclude noisy/aggressive tags; `-itags` include.
- `-H 'Cookie: ...'` auth for gated endpoints. Experimental `-ai "<prompt>"` generates a template on the fly.

## Safe invocation
```bash
# High/critical CVEs + exposures over live hosts, rate-limited, JSONL out
nuclei -l live-hosts.txt -tags cve,exposure -severity critical,high,medium \
  -etags dos,intrusive -rl 30 -c 25 -timeout 10 -jsonl -o nuclei.jsonl
```

## Evidence to capture
- Matched template id, matched-at URL, extracted data, severity — straight into
  a finding record (template id + location ≈ the stable fingerprint).
- Treat single hits as leads: re-verify with a safe PoC before reporting confirmed.

## Scope & rate caveats
- Scan ONLY in-scope hosts/URLs. Keep `-rl` modest and exclude `dos`/`intrusive`
  tags unless the Rules of Engagement explicitly permit aggressive checks.
- Keep templates updated, but pin a known template set per run for reproducible,
  diffable results across scans.
- Some templates send real payloads — review tags; the no-DoS limit still applies.
