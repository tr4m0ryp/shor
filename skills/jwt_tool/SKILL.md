---
name: jwt_tool
description: "[exploit] Inspect and attack JSON Web Tokens — alg:none, key confusion (RS256→HS256), weak-secret cracking, claim tampering. Reach for it whenever the app authenticates with JWTs to test signature and verification flaws."
---

# jwt_tool — JWT analysis & attacks

`jwt_tool` (Python; **pinned git clone** in `tools.lock`, run in place from
`/opt/aegis/tools/jwt_tool`, e.g. `python jwt_tool.py`). Decodes JWTs and runs the
canonical attacks. **Live → exploitation (auth) phase.** Prove a verification flaw
with a single read of a protected resource — do not forge admin tokens to mutate.

## When to reach for it
- The session/auth uses a JWT (Bearer or cookie) and you need to test whether the
  server actually verifies it correctly.
- To check `alg:none`, RS256→HS256 key confusion, weak HMAC secrets, and whether
  claim tampering (`role`, `sub`, `aud`) is rejected.

## Key flags / modes
- `jwt_tool <TOKEN>` decode + show claims.
- `-X a` exploit alg:none; `-X k -pk public.pem` key-confusion (HMAC-sign with the
  RSA public key); `-X i` inject/tamper claims.
- `-C -d <wordlist>` crack the HMAC secret (dictionary).
- `-T` tamper interactively; `-S hs256 -p <secret>` re-sign; `-I -pc <claim> -pv <val>` set a claim.
- `-t <url> -rh "Authorization: Bearer <T>"` send the crafted token at a live request to test acceptance.

## Safe invocation
```bash
# Decode, then test alg:none acceptance against a protected endpoint
jwt_tool "$JWT"                       # inspect header.alg / claims
jwt_tool "$JWT" -X a -t "https://target.example.com/api/me" \
  -rh "Authorization: Bearer <crafted>"
# Weak-secret crack (offline): jwt_tool "$JWT" -C -d wordlist.txt
```

## Evidence to capture
- Original header `alg` + claims, the crafted token, and the server's response
  proving acceptance (a 200 reading a protected/admin resource). Map to CWE-347
  (improper signature verification) / CWE-287.
- For weak secrets: the cracked key (treat as sensitive) and how it was found.

## Scope & rate caveats
- Test ONLY in-scope tokens/endpoints. Prove the flaw with a single read; NEVER
  forge an elevated token to perform writes or persist access (Rules of Engagement).
- Secret cracking is offline/CPU-bound (no target load); live-acceptance tests are
  few requests — still honor no-DoS limits. Pinned commit keeps runs reproducible.
- Redact tokens/secrets in evidence (first chars + `...REDACTED`).
