---
name: nosqli
description: "[exploit] Detect and exploit NoSQL injection (primarily MongoDB-style operator injection) on a live endpoint. Reach for it when the backend is a NoSQL store and login/query params may accept operator payloads."
---

# nosqli — NoSQL injection scanner

`nosqli` (Go; **pinned git-clone commit** in `tools.lock` — the project is years
stale and has no documented `@latest`). Targets NoSQL (chiefly MongoDB) operator
injection such as auth bypass via `$ne`/`$gt` and boolean/error-based extraction.
**Live → exploitation phase.**

## When to reach for it
- Recon/semgrep indicate a MongoDB (or similar) backend and user input reaches a
  query/filter — especially login and search endpoints.
- To test operator-injection auth bypass and confirm injectable params.

## Key flags
- `nosqli scan -t "<url>"` target URL (subcommand-style CLI).
- `-r req.txt` request file; `-p <param>` focus a parameter; `-u`/`-w` user/pass field hints.
- `--method GET|POST`; flag surface is minimal and version-specific.
- Verify everything with `nosqli --help` / `nosqli scan --help` before relying on a flag.

## Safe invocation
```bash
# Scan a login endpoint for NoSQL operator injection
nosqli scan -t "https://target.example.com/api/login" --method POST
```
> Stale tool: confirm the exact subcommand/flags with `--help`. If a flag is
> uncertain, fall back to a manual curl operator probe (below) and say so.

Manual cross-check (MongoDB operator-injection auth bypass):
```bash
curl -sS "https://target.example.com/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"user":"admin","pass":{"$ne":null}}'
```

## Evidence to capture
- The injectable param + payload (e.g. `{"$ne":null}` returning an authed session),
  exact request/response. Map to CWE-943 (improper neutralization in a data query).
- A single auth-bypass or one extracted record is sufficient proof.

## Scope & rate caveats
- Target ONLY the in-scope endpoint. Prove with one bypass/record; never bulk-dump.
- Stale, low-maintenance tool — treat output skeptically and corroborate with a
  manual curl probe; pinned commit keeps runs reproducible.
- Throttle; honor per-host no-DoS limits.
