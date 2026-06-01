---
name: authz-recipe
description: "[exploit] Broken-access-control recipe (IDOR/BOLA/BFLA, the OWASP #1 with no headless CLI) — build a role x endpoint matrix, A/B-replay requests across identities, and enumerate object IDs. Reach for it for every authorization test."
---

# authz-recipe — broken access control (IDOR / BOLA / BFLA)

Broken Access Control is OWASP #1, but there is **no drop-in CLI** (Autorize /
AuthMatrix are Burp extensions). This is the procedure that carries the whole
category: an **authorization-matrix + A/B session-replay** method driving `curl`,
the `playwright` skill (per-identity sessions), and `ffuf` (ID enumeration).
**Live → exploitation phase.** Read-only, minimum-impact, capped enumeration.

The bug is always the same shape: **a request that one identity is allowed to make
returns the same data/effect when replayed as a different (lower-priv or peer)
identity.** Prove that, minimally, and stop.

## Identity set (establish first)
Spin up isolated sessions — never share cookies (use `playwright -s=<label>` or
distinct curl cookie jars):

| Identity | Role | Purpose |
|---|---|---|
| `victim_low` | low-priv A | owns one known object you control (the reference) |
| `attacker_low` | low-priv B (peer) | replays victim_low's requests (horizontal IDOR/BOLA) |
| `attacker_admin` | privileged (if available) | baseline for the *expected* authorized response |
| `anonymous` | none | tests whether auth is enforced at all |

Verify each session is alive (`GET /me`) before use. If only one account exists,
cross-identity findings are POTENTIAL (`blocker: only one account provisioned`).

## Step 1 — Role x endpoint matrix (from recon)
From the recon deliverable (esp. its API inventory, roles, and IDOR/object-ID
candidates), build the ground truth — `(role, endpoint, expected allow|deny)`
triples — and an **identifier map**: for each endpoint, every ID it accepts in
path / query / JSON body / form / header / GraphQL variable.

```
GET  /api/users/{id}        user: own only   admin: any
GET  /api/orgs/{org}/members member of org    admin: any
POST /admin/users           admin only
```

## Step 2 — A/B session replay (the core test)
Capture a request as the **owning/high-priv** identity, then replay it **verbatim**
swapping only the session, and **diff** the responses.

```bash
# Baseline: victim_low reads its own object (200, returns victim's data)
curl -sS -b "$VICTIM_JAR" "https://target.example.com/api/orders/1001" -o a.json -w "%{http_code}\n"
# Replay: attacker_low (peer) requests the SAME object, only the cookie changes
curl -sS -b "$ATTACKER_JAR" "https://target.example.com/api/orders/1001" -o b.json -w "%{http_code}\n"
diff a.json b.json    # identical 200 body => horizontal IDOR (CWE-639)
```
- **Horizontal (BOLA, CWE-639):** attacker_low gets victim_low's object → leak.
- **Vertical (BFLA, CWE-862/863):** attacker_low (or anonymous) gets a 200 from an
  admin-only endpoint that should be 401/403 (diff against attacker_admin baseline).
- Also try the identifier in **every** location, **HTTP verb tampering**
  (GET↔POST↔PUT/PATCH/DELETE — frameworks often guard only the documented verb),
  context headers (`X-User-Id`, `X-Org-Id`), and ID encodings (int/UUID/base64).

## Step 3 — Object-ID enumeration (ffuf, capped)
Use `ffuf` (see the `ffuf` skill) to prove IDs belonging to *other* identities are
reachable — to demonstrate a **pattern**, not to harvest data.

```bash
# As attacker_low, walk a few neighboring order IDs; flag any 200 that is not theirs
ffuf -u "https://target.example.com/api/orders/FUZZ" \
  -w <(seq 1000 1002) -b "$ATTACKER_JAR" \
  -mc 200 -fr "attacker_low_marker" -rate 2 -o idor.json -of json
```
For UUID/slug IDs, feed a small list of known *other-identity* IDs (collected from
your own accounts) rather than brute force. **≤3 sequential IDs to prove
predictability, then STOP.**

## Step 4 — Verify each 200 actually leaks
A 200 is not proof on its own. Confirm the response **belongs to another identity**:
it contains victim_low's email/order/owner fields, and differs from attacker_low's
own object at the same endpoint. Capture ONE such record (PII redacted). That is
Level-3 EXPLOITED; do not collect more "for completeness".

## Evidence to capture
- The identity set (roles + **redacted** tokens, what each owns).
- The A/B pair: identical request, two sessions, two responses, the diff.
- For vertical: a role-matrix table (anonymous / attacker_low / attacker_admin → status).
- ONE other-identity record proving the leak, sensitive fields `[REDACTED]`.
- Map to CWE-639 / CWE-862 / CWE-863 / CWE-285 and OWASP API1/API5:2023.

## Scope & rate caveats (non-negotiable)
- **READ-ONLY by default.** Prefer GET/HEAD/OPTIONS. No DELETE/PUT/PATCH/mutating
  POST against any object you do not own; cross-tenant proof is a read demonstration.
- **No bulk PII / no enumeration beyond proof.** One record, sensitive fields
  redacted; never dump a table; ≤3 sequential IDs.
- **Rate ≤2 req/sec** per endpoint, single-threaded; never trip account lockouts.
- **No privilege persistence** — if you reach admin, read one admin-only resource as
  proof, then stop; do not create accounts, alter ACLs, or change real passwords.
- Test ONLY in-scope endpoints; keep every identity's session strictly isolated.
