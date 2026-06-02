---
name: kxss
description: "[recon/exploit] Fast reflected-XSS triage — reports which parameters reflect XSS-significant characters (<>\"'`) unescaped. Reach for it to cheaply shortlist promising params before deep dalfox/xsstrike runs."
---

# kxss — reflected-XSS character triage

`kxss` (Go, `go install`). Lightweight first pass: for each URL/param it checks
which of the XSS-significant characters (`< > " ' ` ( )`) reflect back unescaped.
It does NOT confirm execution — it points dalfox/xsstrike at the parameters worth
the heavier scan. **Live; recon→exploitation handoff.**

## When to reach for it
- You have many parameterized URLs (katana/gau/waybackurls) and want to quickly
  rank which params reflect unfiltered, before spending dalfox time.

## Usage
- Reads URLs (with params) on stdin; prints reflected params + which chars survive.
- Minimal flags by design; commonly fed from `waybackurls`/`gau` via a param-cleaner
  like `qsreplace`.

## Safe invocation
```bash
# Triage parameterized URLs; show params reflecting unfiltered XSS chars
cat params.txt | kxss | tee kxss.txt
# Typical chain:
# waybackurls target.example.com | grep '=' | qsreplace '"><svg' | kxss
```

## Evidence to capture
- The URL + parameter + the set of unescaped reflected characters.
- This is a **lead**, not a finding — promising params graduate to dalfox/xsstrike
  for a verified, executing PoC before anything is reported (CWE-79).

## Scope & rate caveats
- Feed it ONLY in-scope URLs (filter the historical/recon lists for scope first).
- It sends one-ish request per URL but lists can be huge — throttle upstream and
  cap the input to respect no-DoS limits.
- Reflection of a character is not XSS; never report kxss output as a confirmed vuln.
