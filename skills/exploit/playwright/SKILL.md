---
name: playwright
description: "[recon/exploit] Headless browser automation — drive auth flows, render JS apps, and CONFIRM client-side bugs (XSS execution, DOM sinks) in a real DOM. Reach for it whenever proof requires JavaScript to actually run."
---

# playwright — headless browser driver

Headless Chromium via Playwright (installed `pip install playwright &&
playwright install chromium`, with glibc font/nss deps). Use it to interact with
JS-heavy apps, complete login/SSO/multi-step flows for an authenticated session,
and — critically — to **prove** client-side findings by observing real execution
(an XSS `alert`/dialog, a DOM mutation) that a raw HTTP tool cannot demonstrate.

## When to reach for it
- Establish/persist an authenticated session (cookies + storage) other tools reuse.
- Confirm reflected/DOM/stored XSS actually executes (dialog fired, sink reached).
- Map SPA endpoints/state that only appear after JS runs; capture network requests.
- Drive CSRF-token or wizard flows curl can't easily replay.

## Session isolation (load-bearing)
Run every identity in its **own labeled session** so cookies never bleed across
identities — essential for the authz A/B replay (`-s=victim_low`, `-s=attacker_low`).
The exact driver is provided in-image (e.g. a `playwright-cli`/MCP wrapper); always
pass the session label and prefer accessibility **snapshots** over screenshots for
reasoning. Verify the available commands from the in-image CLI's own help.

## Typical actions
- navigate, snapshot (DOM/accessibility tree), click/fill/press by ref, evaluate JS.
- cookie/localStorage get/set (inject a captured session, e.g. for takeover proof).
- save/load storage state per session; capture console + network requests; screenshot.

## Safe invocation (illustrative)
```bash
# Per-identity session: log in, save state, then reuse it for scoped testing
playwright-cli -s=victim_low open https://target.example.com/login
playwright-cli -s=victim_low snapshot
playwright-cli -s=victim_low fill e1 "$TEST_USER" ; playwright-cli -s=victim_low fill e2 "$TEST_PASS" --submit
playwright-cli -s=victim_low state-save victim_low.json
# XSS proof: navigate to the payload URL and capture the dialog/DOM
playwright-cli -s=attacker_low goto "https://target.example.com/search?q=<payload>"
```
> Driver/flags vary by in-image build — run its `--help` and adapt; don't assume.

## Evidence to capture
- For XSS: the console/dialog event or DOM snapshot showing the payload executed.
- For auth: the post-login authenticated view proving the session/identity.
- Saved storage-state files per identity (reused by curl/ffuf for replay).

## Scope & rate caveats
- Navigate ONLY to in-scope origins; a real browser will fetch third-party assets,
  but do not drive it against out-of-scope hosts.
- Heavier than HTTP tools — use deliberately, not for bulk crawling (that's katana).
- Keep sessions strictly per-identity; never share one session across roles, or the
  authz diff is invalid. Redact captured tokens/cookies in evidence.
