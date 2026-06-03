---
name: nmap
description: "[recon] Deep port/service/version scanning and scripted enumeration of in-scope hosts. Reach for it after naabu to accurately fingerprint services, versions, and run safe NSE checks."
---

# nmap — service/version fingerprinting

The reference port scanner. In this pipeline nmap is the *accurate* pass: run it
against the open ports naabu already found, not as a wide sweep.

## When to reach for it
- To get exact service + version on confirmed-open ports.
- For default-script enumeration (titles, certs, headers, banners).
- To characterize TLS, supported methods, and obvious misconfigs.

## Key flags
- `-p <ports>` specific ports (use naabu's open list, not `-p-` blindly).
- `-sV` version detection; `-sC` default safe NSE scripts; `-A` aggressive (OS+scripts+traceroute).
- `-Pn` skip host discovery (assume up); `-T3`/`-T4` timing (higher = louder).
- `-oA <base>` write all formats (`.nmap/.gnmap/.xml`); `-oX` XML for parsing.
- `--script <cat>` run NSE; prefer `safe` category. AVOID `--script vuln`/`exploit`
  /`brute`/`dos` unless the RoE explicitly allows active checks.

## Safe invocation
```bash
# Version + safe default scripts on naabu-confirmed ports, all output formats
nmap -sV -sC -Pn -T3 -p 80,443,8080 target.example.com -oA nmap/target
```

## Evidence to capture
- The `-oA` XML/grepable output: service, product, version, NSE script results.
- Version strings map to CVEs (hand to nuclei / osv context); cert SANs add hosts.

## Scope & rate caveats
- Scan ONLY in-scope hosts. `-A` and aggressive timing are loud — prefer `-T3`,
  targeted ports, and `safe` scripts to respect no-DoS limits.
- NSE has dangerous categories: never run `dos`, `exploit`, `brute` without
  explicit authorization in the Rules of Engagement.
- Re-validate the target against the RoE immediately before scanning.
