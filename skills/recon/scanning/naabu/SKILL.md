---
name: naabu
description: "[recon] Fast SYN/CONNECT port scanner for hosts/CIDRs (Go, libpcap). Reach for it to find open ports across many hosts quickly, then hand the open services to nmap for deep fingerprinting."
---

# naabu — fast port discovery

ProjectDiscovery's `naabu` (Go; needs `libpcap` for SYN scan). Built for breadth:
sweep many hosts for open ports fast, then feed the survivors to nmap for the
slow, accurate service/version pass.

## When to reach for it
- First port-discovery pass over a host list or CIDR in scope.
- As a pre-filter so nmap only deep-scans confirmed-open ports.

## Use CONNECT mode here, and scan WIDE (IMPORTANT)
- **`-s c` (CONNECT) is MANDATORY in this worker.** The container runs nonroot
  with NO raw-socket privileges, so the default SYN scan (`-s s`) silently
  under-reports — it can return just a port or two and miss everything else.
  Always pass `-s c`.
- **App backends hide above the well-known range.** `-top-ports 100/1000` misses
  common service ports like **8080, 8090, 8000, 3000, 5000, 8443, 9000, 9090** —
  exactly where a reverse-proxied SPA's API, an OIDC provider, or a dev server
  live. Either scan **all ports** (`-p -`) or ADD those app/dev ports explicitly.
  A 2-port result on a real app is a RED FLAG that the scan was too narrow —
  widen it before trusting it.

## Key flags
- `-host <h>` / `-list <file>` targets (hosts or CIDRs).
- `-p 80,443,8080` ports, `-top-ports 100|1000`, or `-p -` all ports.
- `-s c` CONNECT scan (unprivileged — use this) / `-s s` SYN (needs root).
- `-rate <n>` packets/sec — the main throttle.
- `-json` output; `-nmap-cli "nmap -sV"` auto-hand-off to nmap on found ports.
- `-exclude-ports`, `-ep`, `-exclude-cdn` skip CDN IPs (port-scanning a CDN is noise).

## Safe invocation
```bash
# CONNECT scan, ALL ports + explicit app/dev ports, modest rate, JSON.
# (-p - is the thorough default here; drop to -top-ports 1000 plus the app
#  ports only when full-range is too slow for the target.)
naabu -list hosts.txt -s c -p - -rate 1000 -exclude-cdn -json -o ports.jsonl
# Faster fallback if -p - is too slow — top-1000 PLUS the common app ports:
naabu -list hosts.txt -s c -top-ports 1000 -p 8080,8090,8000,3000,5000,8443,9000,9090 \
  -rate 1000 -json -o ports.jsonl
```

## Evidence to capture
- host:port open list (provenance + nmap targeting input).
- Unexpected open ports (admin panels, DBs, internal services) = priority leads.

## Scope & rate caveats
- Port scanning is active and noisy. Scan ONLY in-scope hosts/CIDRs; never sweep
  a CDN or shared-hosting range that pulls in third parties (`-exclude-cdn`).
- `-rate` is a no-DoS lever — keep it conservative; high rates can trip IDS or
  saturate small targets. Stop if the host degrades.
- SYN scan needs raw-socket privileges; in a constrained sandbox use `-s c`.
