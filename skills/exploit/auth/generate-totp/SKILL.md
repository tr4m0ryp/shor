---
name: generate-totp
description: "[exploit] Generate a current 6-digit TOTP (RFC 6238) from a provided MFA secret, to complete logins for in-scope test accounts that have 2FA enabled. Reach for it during authenticated-session setup, not as an attack."
---

# generate-totp — TOTP code generator

Shor's bundled `generate-totp` CLI (RFC 6238 TOTP / RFC 4226 HOTP). It turns a
base32 MFA seed — supplied for an **in-scope test account** in the project's auth
config — into the current 6-digit code so the agent can finish a 2FA-gated login
and obtain an authenticated session. This is a login helper, not an exploit.

## When to reach for it
- Establishing an authenticated session for a test account whose login requires a
  TOTP second factor (the login instructions reference `$totp`).
- Re-generating a fresh code when the previous one expired mid-login.

## Usage
- `generate-totp --secret <BASE32_SECRET>` — secret must be base32 (`A-Z`, `2-7`);
  other characters are stripped. Prints JSON to stdout:
  `{"status":"success","totpCode":"123456","expiresIn":17}` where `expiresIn` is
  seconds until the code rotates. On bad input: `{"status":"error","message":...}`.

## Safe invocation
```bash
# Generate the current code for an in-scope test account's MFA seed
generate-totp --secret JBSWY3DPEHPK3PXP
# -> {"status":"success","totpCode":"492039","expiresIn":11}
# Parse: TOTP=$(generate-totp --secret "$SEED" | jq -r .totpCode)
```

## Evidence to capture
- Usually none for the finding itself — it is session plumbing. If a 2FA *weakness*
  is the finding (e.g. code reuse, no replay protection, oversized window), capture
  that behavior via the login flow, not this tool's output.

## Scope & rate caveats
- Use ONLY seeds the operator supplied for in-scope test accounts. Never generate
  codes for secrets discovered/leaked from the target or for third-party accounts.
- The secret is sensitive: it comes from the secrets layer, stays out of logs/
  findings, and must not be echoed or interpolated into prompt text (secret-hygiene).
- If `expiresIn` is very low, regenerate to avoid a stale-code login failure.
