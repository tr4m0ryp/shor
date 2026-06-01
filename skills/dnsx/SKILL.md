---
name: dnsx
description: "[recon] Fast DNS resolver/toolkit — bulk-resolve hostnames, query record types, and run DNS brute force. Reach for it to filter a candidate subdomain list down to live, resolving hosts."
---

# dnsx — fast DNS resolution & queries

ProjectDiscovery's `dnsx` (pure-Go). Resolves large host lists and queries
record types at speed. Sits between subfinder (discover) and httpx (probe).

## When to reach for it
- To drop non-resolving entries from a subfinder list before probing.
- To pull A/AAAA/CNAME/MX/TXT/NS records for the attack-surface map.
- For wordlist-based subdomain brute force when passive sources are thin.

## Key flags
- `-l <file>` / stdin — host list.
- `-a -aaaa -cname -mx -ns -txt -ptr` record types; `-resp` show the answer.
- `-silent` domains only; `-json` structured output.
- `-d <domain> -w <wordlist>` DNS brute force (active).
- `-rl <n>` rate limit; `-t <n>` concurrency; `-r <resolvers.txt>` custom resolvers.

## Safe invocation
```bash
# Resolve candidates, keep only live hosts with their A records, as JSON
dnsx -l candidates.txt -a -cname -resp -json -rl 100 -o resolved.jsonl
```

## Evidence to capture
- Resolved host → IP/CNAME mapping (feeds nmap/naabu targeting and httpx).
- CNAMEs pointing at deprovisioned third-party services = subdomain-takeover lead.

## Scope & rate caveats
- Plain resolution is low-impact, but DNS brute force (`-w`) generates many
  queries — keep `-rl` sane and run it only against in-scope apexes.
- Brute-forced hosts are candidates; re-validate scope before probing/attacking.
- Use trusted resolvers; public-resolver rate limits can poison results under load.
