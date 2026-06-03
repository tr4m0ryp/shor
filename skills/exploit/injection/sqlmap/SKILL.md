---
name: sqlmap
description: "[exploit] Automated SQL injection detection and exploitation against a live endpoint. Reach for it after manual curl confirmation to fingerprint the DB, enumerate schema, and extract a minimal proof sample."
---

# sqlmap — SQL injection exploitation

`sqlmap` (Python; run in place: `python /opt/shor/tools/sqlmap/sqlmap.py` or the
`sqlmap` wrapper). The standard for confirming and exploiting SQLi. Workflow:
confirm the point manually with curl, then bring sqlmap in for enumeration and a
bounded data sample. **Live → exploitation phase.**

## When to reach for it
- After a manual probe (`'`, boolean, time delay) suggests an injectable param.
- To fingerprint DB type/version, enumerate tables/columns, and prove impact with
  a small sample (e.g. version + 5 rows from one sensitive table).

## Key flags
- `-u "<url>"` target (mark injection with `*`), or `-r req.txt` raw request file.
- `--data`, `--cookie`, `-H` for POST/auth; `-p <param>` target a specific param.
- `--dbms <type>`, `--level 1-5`, `--risk 1-3` (keep low unless RoE allows higher).
- `--batch` non-interactive defaults; `--threads <n>`; `--delay <s>`; `--time-sec <s>`.
- Enumeration: `--banner --current-user --current-db --dbs --tables --columns --dump`.
- `--tamper=<script>` WAF evasion (pair with wafw00f result); `--technique=BEUSTQ`.

## Safe invocation
```bash
# Confirm + fingerprint one param non-interactively, low risk, throttled
sqlmap -u "https://target.example.com/item?id=1" -p id \
  --batch --level 2 --risk 1 --delay 1 --banner --current-db --dbs
# Then, scoped extraction (one table, capped rows):
# sqlmap -r req.txt -p id --batch -D appdb -T users --dump --start 1 --stop 5
```

## Evidence to capture
- The confirming payload/technique, DBMS + version, the exact request.
- A **minimal** data sample (e.g. first 5 rows of one sensitive table) with PII
  redacted — smallest convincing proof, not a full dump. Map to CWE-89.

## Scope & rate caveats
- Target ONLY the in-scope endpoint. `--dump` is destructive to privacy: extract
  the **minimum** sample (`--start/--stop`), redact PII, then STOP.
- Keep `--risk`/`--level` low and use `--delay`/`--time-sec` to honor no-DoS
  limits. Never use `--os-shell`/`--os-cmd`/`--sql-shell` to mutate or pivot
  unless explicitly authorized in the Rules of Engagement.
- `--threads` high + time-based blind = heavy load; throttle.
