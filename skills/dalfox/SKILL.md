---
name: dalfox
description: "[exploit] Fast parameter-analysis XSS scanner with DOM/reflection verification (Go). Reach for it as the primary XSS tool to confirm reflected/DOM XSS on parameterized URLs and emit a working PoC payload."
---

# dalfox — XSS scanning & verification

`dalfox` (Go, install via `go install`). Primary XSS scanner: analyzes parameters,
detects reflection contexts, and verifies execution. **Live → exploitation phase.**
Pair with Playwright when you need to *prove* the payload actually executes in a
real DOM.

## When to reach for it
- Confirm reflected or DOM XSS on URLs/params from katana/gau/arjun.
- Generate a minimal working payload appropriate to the reflection context.

## Key flags / modes
- `url <target>` single URL; `pipe` read URLs from stdin; `file <list>` batch.
- `-p <param>` target a parameter; `-b <oob-host>` blind-XSS callback (interactsh).
- `--custom-payload <file>`; `--mining-dict`/`--mining-dom` param mining.
- `--cookie`, `-H 'Header: v'`, `--data` for auth/POST.
- `--delay <ms>`, `--worker <n>` concurrency; `--format json` / `-o out` output.
- `--skip-bav` skip basic-auth-vuln checks to reduce noise.

## Safe invocation
```bash
# Verify XSS on a parameterized URL, JSON out, with blind-XSS callback
dalfox url "https://target.example.com/search?q=test" -p q \
  -b "$INTERACTSH_HOST" --delay 200 --format json -o dalfox.json
```
Batch from recon: `cat katana-params.txt | dalfox pipe --format json -o dalfox.json`.

## Evidence to capture
- The verified payload, the injected parameter, reflection context, and proof of
  execution (dalfox `[POC]` line, or a Playwright dialog/DOM screenshot). Map to CWE-79.
- For blind XSS: the interactsh callback row (nonce + source) confirming fire.

## Scope & rate caveats
- Scan ONLY in-scope URLs. Use `--delay`/`--worker` to honor no-DoS limits — param
  mining + payload sets fan out quickly.
- Stop at one verified PoC per injection point; do not mass-fire payloads.
- Stored-XSS proof should avoid persisting noisy/destructive markup — use a unique
  benign nonce payload.
