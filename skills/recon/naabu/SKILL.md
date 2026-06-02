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

## Key flags
- `-host <h>` / `-list <file>` targets (hosts or CIDRs).
- `-p 80,443,8080` ports, `-top-ports 100|1000`, or `-p -` all ports.
- `-s s` SYN (default, needs privileges) / `-s c` CONNECT scan (unprivileged).
- `-rate <n>` packets/sec — the main throttle.
- `-json` output; `-nmap-cli "nmap -sV"` auto-hand-off to nmap on found ports.
- `-exclude-ports`, `-ep`, `-exclude-cdn` skip CDN IPs (port-scanning a CDN is noise).

## Safe invocation
```bash
# Top-1000 ports over in-scope hosts, modest rate, JSON, skip CDN edges
naabu -list hosts.txt -top-ports 1000 -rate 1000 -exclude-cdn -json -o ports.jsonl
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
