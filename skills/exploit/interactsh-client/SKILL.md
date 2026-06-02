---
name: interactsh-client
description: "[exploit] Out-of-band (OAST) interaction listener — generates a unique callback domain and logs DNS/HTTP/SMTP hits to it. Reach for it to confirm blind SSRF/RCE/XXE/blind-XSS where no response comes back in-band."
---

# interactsh-client — OOB/OAST confirmation

ProjectDiscovery's `interactsh-client` (Go, `go install`). Mints a unique
interaction domain and records any DNS/HTTP/SMTP callback to it. The standard way
to prove **blind** vulnerabilities: plant a unique-nonce subdomain in a payload,
trigger it, and watch for the hit. **Live → exploitation phase.** Pairs with
ssrfmap, nuclei `-b`, dalfox `-b`, and manual blind probes.

## When to reach for it
- Blind SSRF (no body returned), blind RCE/command-exec, blind XXE, blind/stored
  XSS — anywhere only an out-of-band signal can confirm the bug.

## Key flags
- `-json` structured per-interaction output (prefer for parsing).
- `-o out.jsonl` persist interactions; `-v` verbose.
- `-s <server>` self-hosted interactsh server (else the public default);
  `-n <n>` number of payloads to pre-generate.
- `-poll-interval <s>` polling cadence. On start it prints the payload domain to use.

## Safe invocation
```bash
# Start the listener; copy the printed payload domain into your SSRF/RCE payload
interactsh-client -json -o interactions.jsonl
# It prints e.g. cXXXX.oast.fun — embed a unique nonce per probe:
#   url=http://$(openssl rand -hex 4).cXXXX.oast.fun/
```

## Evidence to capture
- The interaction record: protocol (DNS/HTTP), the unique nonce subdomain, the
  **source IP**, and timestamp. A callback from the target's egress IP carrying
  your nonce is the proof that closes a blind finding.

## Scope & rate caveats
- The callback domain must be reachable from the target — OOB confirmation needs
  outbound egress to be allowed; if egress is locked down, OOB may not fire (note
  this as a blocker rather than concluding "not vulnerable").
- Use a fresh nonce per probe so callbacks are unambiguous. This tool only listens;
  it generates no target load. Prefer the self-hosted `-s` server when policy
  forbids third-party OAST infrastructure.
