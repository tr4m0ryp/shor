---
name: hydra
description: "[exploit] Network login brute-forcer for protocol services (SSH, FTP, RDP, SMTP, DB, and HTTP form/basic). Reach for it to test credential strength on an authenticated, in-scope login when ffuf isn't the right fit."
---

# hydra — network login brute force

`hydra` (THC-Hydra). Parallelized credential attacks across many protocols. For
plain HTTP login fuzzing, `ffuf` is usually cleaner; reach for hydra when the
login is a non-HTTP protocol service or you want hydra's HTTP form module.
**Live → exploitation (auth/credential) phase.** Use small, targeted wordlists.

## When to reach for it
- An in-scope service exposes a login (SSH/FTP/RDP/SMTP/IMAP/MySQL/Postgres/etc.)
  and you must demonstrate weak or default credentials.
- HTTP form/basic auth where you prefer hydra's `http-post-form` matcher.

## Key flags
- `-l <user>` / `-L <userlist>`; `-p <pass>` / `-P <passlist>`; `-C user:pass` combos.
- `-s <port>`, `-t <n>` parallel tasks (keep low), `-f` stop at first valid pair.
- `-w <sec>` wait/timeout; `-V` verbose (show each try); `-o out.txt` log.
- Service spec: `hydra <opts> <host> <module>` (e.g. `ssh`, `ftp`,
  `http-post-form "/login:user=^USER^&pass=^PASS^:F=invalid"`).

## Safe invocation
```bash
# Test a small credential set against an in-scope SSH service, stop on first hit
hydra -l testuser -P small-passlist.txt -t 4 -f -V \
  ssh://target.example.com
# HTTP form example (adjust path/fields/fail-string):
# hydra -l admin -P small-passlist.txt target.example.com \
#   http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"
```

## Evidence to capture
- The valid `user:pass` pair found (credential redacted in the report), the service,
  and that it authenticated. Map to CWE-307 (improper restriction of auth attempts)
  / CWE-521 (weak credentials).

## Scope & rate caveats
- HIGH-RISK / NOISY. Target ONLY in-scope services. Keep `-t` low and wordlists
  SMALL and targeted — large/high-concurrency runs are a DoS and trip lockouts;
  the no-DoS limit is strict here.
- NEVER intentionally lock out real accounts; prefer known test accounts and `-f`
  to stop at first success. Confirm the Rules of Engagement permit credential
  brute force before running — many programs forbid it.
