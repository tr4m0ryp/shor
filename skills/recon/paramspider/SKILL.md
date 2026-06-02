---
name: paramspider
description: "[recon] Mine parameterized URLs for a domain from web archives and normalize them into FUZZ-ready templates (passive). Reach for it to bulk-harvest historical param names/URLs as fuzzing seeds."
---

# paramspider — archived parameter URL mining

`paramspider` (Python, shared venv). Pulls URLs that contain query parameters
from web archives for a domain and rewrites the values to a placeholder, giving
ready-to-fuzz templates. Passive: it reads archives, not the target. Complements
`arjun` (which actively probes a single live endpoint).

## When to reach for it
- To get a broad, domain-wide list of parameterized URLs cheaply and passively.
- To produce FUZZ/placeholder templates to drop straight into ffuf/nuclei/dalfox.

## Key flags
- `-d <domain>` / `--domain` target.
- `-s` / `--subs` include subdomains (flag name varies by fork — check `--help`).
- `-p <str>` placeholder to inject in place of param values (e.g. `FUZZ`).
- `-o <file>` output path; some forks write `results/<domain>.txt` by default.
- `--level` / exclude-extension flags vary by fork — verify with `paramspider --help`.

## Safe invocation
```bash
# Harvest parameterized URLs for the domain, FUZZ placeholder, to a file
paramspider -d target.example.com -p FUZZ -o paramspider.txt
```
> Forks differ on flag names/output. Run `paramspider --help` first and adapt.

## Evidence to capture
- The parameterized-URL list (provenance for param/value fuzzing candidates).
- Param names recurring across endpoints (likely shared backend handlers).

## Scope & rate caveats
- Archive-sourced and historical — re-probe with httpx and re-validate scope
  before fuzzing any URL it returns.
- Passive on the target; only the archive provider sees traffic.
- This forks frequently and flag names drift — confirm flags via `--help` rather
  than assuming; if a flag is uncertain, say so instead of guessing.
