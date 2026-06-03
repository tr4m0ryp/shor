---
name: xsstrike
description: "[exploit] Context-aware XSS suite with payload generation, WAF detection, and fuzzing. Reach for it as a secondary XSS tool when dalfox is inconclusive or you need crafted, context-specific payloads/WAF bypass."
---

# XSStrike — advanced XSS detection

`XSStrike` (Python; pinned git clone, run in place from `/opt/shor/tools/XSStrike`,
e.g. `python xsstrike.py`). Context-aware analysis with intelligent payload
generation, reflection/DOM checks, fuzzing, and WAF fingerprinting. Secondary to
dalfox; reach for it when dalfox is inconclusive or a hand-crafted bypass is
needed. **Live → exploitation phase.**

## When to reach for it
- dalfox flags reflection but cannot land a working payload (tricky context/WAF).
- You want generated context-specific payloads or DOM-XSS analysis on one URL.

## Key flags
- `-u "<url>"` target; `--data "k=v"` POST body.
- `--params` mine parameters; `--crawl` crawl then test; `-l <n>` crawl depth.
- `--fuzzer` fuzz a parameter; `--blind` blind-XSS (set payload in core/config).
- `--headers` send custom/auth headers (interactive or via stdin).
- `-t <n>` threads; `-d <sec>` delay; `--timeout <s>`.

## Safe invocation
```bash
# Test a single in-scope URL, throttled
xsstrike -u "https://target.example.com/search?q=test" -t 5 -d 1
```

## Evidence to capture
- The generated payload that fired, the reflection context, and execution proof
  (XSStrike's confirmation line, or a Playwright DOM/dialog capture). Map to CWE-79.
- The detected WAF (if any) and the bypass technique that worked.

## Scope & rate caveats
- Scan ONLY in-scope URLs. `--crawl` + `--fuzzer` generate lots of traffic — set
  `-t`/`-d` to honor no-DoS limits.
- Stop at one verified PoC per injection point.
- Pinned to a `tools.lock` SHA; run in place rather than re-installing.
