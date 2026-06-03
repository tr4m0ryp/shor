---
name: ffuf
description: "[recon/exploit] Fast HTTP fuzzer — content/dir discovery, parameter & value fuzzing, and login/credential brute via the FUZZ keyword. Reach for it for forced browsing and (with the authz recipe) ID enumeration."
---

# ffuf — HTTP fuzzer

`ffuf` (pure-Go). Anywhere a request has a fuzzable spot, mark it `FUZZ` and
ffuf iterates a wordlist there. Used for content discovery, vhost/param/value
fuzzing, HTTP login brute, and — driven by the authz recipe — object-ID
enumeration for IDOR/BOLA.

## When to reach for it
- Directory/file discovery (forced browsing) on a live host.
- Parameter-name and parameter-value fuzzing.
- Credential brute over HTTP login forms (auth layer).
- IDOR/BOLA ID sweeps (see the `authz-recipe` skill — capped, read-only).

## Key flags
- `-u <url-with-FUZZ>` target; `-w <wordlist>` (`-w list:KEY` for named/multiple).
- `-mc 200,301` match codes; `-fc 404` filter; `-fs <n>` / `-fw <n>` filter by size/word count (kill boilerplate 200s).
- `-X POST -d 'user=admin&pass=FUZZ'` body fuzz; `-H 'Header: FUZZ'`; `-b 'cookie'` auth.
- `-rate <n>` requests/sec; `-t <n>` threads; `-p <s>` per-request delay.
- `-o out.json -of json` structured output; `-ac` auto-calibrate filtering.
- `-recursion -recursion-depth <n>` (use sparingly — multiplies traffic).

## Safe invocation
```bash
# Content discovery, filter 404s, calibrated, rate-limited, JSON out
ffuf -u https://target.example.com/FUZZ -w wordlist.txt \
  -mc 200,204,301,302,401,403 -ac -rate 30 -t 20 -o ffuf.json -of json
```

## Evidence to capture
- Discovered paths/params with status + size (the response that proves the hit).
- For ID enumeration: the request and the 200 that returns *another identity's* object.

## Scope & rate caveats
- Fuzz ONLY in-scope URLs. `-rate` is the no-DoS lever — keep it modest; recursion
  and big wordlists multiply load fast.
- For credential brute / ID enumeration, respect the engagement caps (authz recipe:
  ≤3 sequential IDs to prove a pattern; ≤2 req/sec). Never bulk-dump real users.
- Always set a `-fs`/`-fw` filter or `-ac`; an unfiltered run buries the real hits.
