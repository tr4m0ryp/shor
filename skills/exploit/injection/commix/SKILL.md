---
name: commix
description: "[exploit] Automated OS command-injection detection and exploitation against a live endpoint. Reach for it after a manual probe suggests user input reaches a shell, to confirm execution with a harmless command."
---

# commix — command injection exploitation

`commix` (Python; run in place: `python /opt/shor/tools/commix/commix.py` or the
`commix` wrapper). Detects and exploits OS command injection. Confirm impact with
a benign, read-only command (e.g. `id`, `whoami`) — do not weaponize. **Live →
exploitation phase.**

## When to reach for it
- After semgrep/recon flags input flowing into a shell/`exec` sink, or a manual
  `;id`/`|whoami`/`$(...)` probe shows command-exec behavior.
- To enumerate which technique works (results-based, blind, time-based) and prove
  execution minimally.

## Key flags
- `-u "<url>"` target, or `-r req.txt` raw request; `--data`, `--cookie`, `-H` for POST/auth.
- `-p <param>` focus a parameter; `--technique=<cetf>` (classic/eval/time/file).
- `--batch` non-interactive; `--level 1-3`; `--delay <s>`; `--time-sec <s>` (blind).
- `--all` enumerate basic host info (keep minimal); `--tamper=<script>` evasion.
- AVOID `--os-cmd=<destructive>`, `--os-shell`, reverse-shell options — proof only.

## Safe invocation
```bash
# Confirm injection on one param with a harmless command, throttled
commix -u "https://target.example.com/ping?host=127.0.0.1" -p host \
  --batch --level 1 --delay 1 --os-cmd="id"
```

## Evidence to capture
- The injectable param + working technique, the exact request, and the **benign**
  command output (e.g. `uid=...` from `id`) proving execution. Map to CWE-78.
- Note the OS/user context; that is sufficient impact — stop there.

## Scope & rate caveats
- Target ONLY the in-scope endpoint. Use read-only commands (`id`, `whoami`,
  `uname`) as proof; NEVER run state-changing commands, fetch files in bulk, open
  a shell, or pivot unless the Rules of Engagement explicitly allow it.
- No background/detached commands. Throttle with `--delay`/`--time-sec` to respect
  no-DoS limits; time-based blind is slow by design.
