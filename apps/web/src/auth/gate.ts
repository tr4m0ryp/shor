// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * App-wide passcode gate — a thin front lock ABOVE the session/dev-login auth.
 *
 * When `SHOR_APP_PASSCODE` is set, every browser-facing request must first carry
 * a valid gate cookie or it is blocked: a GET navigation gets the inline unlock
 * page, anything else gets `401 { error: 'locked' }`. The public read-only share
 * plane (`/share/*`), the gate route itself (`/gate`), and machine clients that
 * present `Authorization: Bearer ...` are EXEMPT. When the passcode is unset/empty
 * the gate is disabled and everything passes (local dev).
 *
 * This layer only decides "locked vs unlocked"; once it passes, the normal
 * `/auth/*` + session flow runs unchanged. It does NOT read, mint, or verify the
 * session cookie and must never weaken the real auth path.
 *
 * Gate cookie (no extra secret): value = HMAC-SHA256(key = SHOR_APP_PASSCODE,
 * msg = "shor-gate-v1") in hex. An incoming cookie is verified by recomputing
 * that HMAC from the env passcode and comparing constant-time — unforgeable
 * without the passcode. Mirrors `auth/session.ts`' use of Node `crypto` +
 * `timingSafeEqual`; kept local so no session helper signature changes.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { getConfig } from '../config.js';

/** Name of the gate cookie (distinct from the session cookie). */
const GATE_COOKIE_NAME = 'shor_gate';
/** Fixed HMAC message — the cookie carries no payload, only this signature. */
const GATE_MESSAGE = 'shor-gate-v1';
/** Gate cookie lifetime: 30 days in seconds. */
const GATE_MAX_AGE = 2592000;

/** Minimal envelope the gate hands back to the router (HTML page or JSON). */
export interface GateResponse {
  readonly status: number;
  readonly body: Record<string, unknown>;
  /** Inline unlock-page HTML; when set the server emits it as `text/html`. */
  readonly html?: string;
  /** A `Set-Cookie` header value to emit on a successful unlock. */
  readonly setCookie?: string;
  /** When set, the server writes a 302 to this `Location`. */
  readonly redirect?: string;
}

/** The configured app passcode (empty string ⇒ gate disabled). */
function passcode(): string {
  return getConfig().appPasscode;
}

/** Whether the gate is active at all (only when a passcode is configured). */
export function isGateEnabled(): boolean {
  return passcode() !== '';
}

/** Length-guarded constant-time string compare (both operands are hex/ascii). */
function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/** Compute the expected gate cookie value from the configured passcode. */
export function gateCookieValue(): string {
  return createHmac('sha256', passcode()).update(GATE_MESSAGE).digest('hex');
}

/**
 * Build the `Set-Cookie` header value carrying the unlock token.
 * HttpOnly + SameSite=Lax + Secure, Path=/, 30-day Max-Age.
 */
export function setGateCookieHeader(): string {
  return [
    `${GATE_COOKIE_NAME}=${gateCookieValue()}`,
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${GATE_MAX_AGE}`,
  ].join('; ');
}

/** Read the gate cookie from a raw `Cookie` request header (or `null`). */
function readGateCookie(cookieHeader: string | undefined): string | null {
  if (!cookieHeader) return null;
  for (const pair of cookieHeader.split(';')) {
    const eq = pair.indexOf('=');
    if (eq < 0) continue;
    if (pair.slice(0, eq).trim() === GATE_COOKIE_NAME) {
      return pair.slice(eq + 1).trim() || null;
    }
  }
  return null;
}

/**
 * Whether a request carries a valid gate cookie. When the gate is disabled this
 * is always true (everything is "unlocked"). Verifies the cookie constant-time
 * against the recomputed HMAC — a forged or stale value fails.
 */
export function isUnlocked(cookieHeader: string | undefined): boolean {
  if (!isGateEnabled()) return true;
  const cookie = readGateCookie(cookieHeader);
  if (!cookie) return false;
  return safeEqual(cookie, gateCookieValue());
}

/**
 * Whether a request bypasses the gate entirely, regardless of cookie state:
 *   - the public read-only share plane (`/share/*`),
 *   - the gate route itself (`/gate`),
 *   - any machine client presenting `Authorization: Bearer ...` (the worker sink
 *     and `/external/*` self-authenticate downstream).
 * Also exempt (returns true) whenever the gate is disabled.
 */
export function isGateExempt(segments: readonly string[], authHeader: string | undefined): boolean {
  if (!isGateEnabled()) return true;
  if (/^Bearer\s+/i.test((authHeader ?? '').trim())) return true;
  const resource = segments[0];
  return resource === 'share' || resource === 'gate';
}

/** Read a passcode from a submitted gate form/JSON body (string field only). */
function submittedPasscode(body: Record<string, unknown>): string {
  const raw = body.passcode;
  return typeof raw === 'string' ? raw : '';
}

/**
 * Render the self-contained unlock page. No external asset deps — the SPA must
 * NOT load while locked. `error` toggles a wrong-passcode message.
 */
export function unlockPageHtml(error = false): string {
  const errorBlock = error ? '<p class="err" role="alert">Incorrect passcode. Try again.</p>' : '';
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="robots" content="noindex, nofollow" />
<title>Shor — Private</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0b0d12; color: #e6e9ef;
    font: 15px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  }
  .card {
    width: 100%; max-width: 360px; padding: 32px 28px; margin: 16px;
    background: #14171f; border: 1px solid #232734; border-radius: 12px;
  }
  h1 { margin: 0 0 6px; font-size: 18px; font-weight: 600; }
  p { margin: 0 0 18px; color: #9aa3b2; font-size: 13px; }
  label { display: block; margin: 0 0 6px; font-size: 12px; color: #9aa3b2; }
  input {
    width: 100%; padding: 10px 12px; border-radius: 8px;
    border: 1px solid #2c3142; background: #0b0d12; color: #e6e9ef; font-size: 14px;
  }
  input:focus { outline: none; border-color: #4f7cff; }
  button {
    width: 100%; margin-top: 14px; padding: 10px 12px; border: 0; border-radius: 8px;
    background: #4f7cff; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer;
  }
  button:hover { background: #3d68ea; }
  .err { margin: 0 0 14px; color: #ff6b6b; font-size: 13px; }
</style>
</head>
<body>
  <main class="card">
    <h1>Private</h1>
    <p>This environment is restricted. Enter the access passcode to continue.</p>
    ${errorBlock}
    <form method="POST" action="/gate">
      <label for="passcode">Passcode</label>
      <input id="passcode" name="passcode" type="password" autocomplete="current-password" autofocus required />
      <button type="submit">Unlock</button>
    </form>
  </main>
</body>
</html>`;
}

/** Wrap the unlock page in a 200 HTML response. */
function unlockPageResponse(error = false): GateResponse {
  return { status: 200, body: {}, html: unlockPageHtml(error) };
}

/**
 * The blocked response for a NON-exempt, locked request that is not the gate
 * route: an HTML navigation (Accept: text/html) gets the unlock page; anything
 * else gets `401 { error: 'locked' }`.
 */
export function blockedResponse(acceptHeader: string | undefined): GateResponse {
  if ((acceptHeader ?? '').includes('text/html')) return unlockPageResponse(false);
  return { status: 401, body: { error: 'locked' } };
}

/**
 * Handle the gate route:
 *   - `GET  /gate` → the unlock page.
 *   - `POST /gate` (form or JSON `{ passcode }`) → constant-time compare to the
 *     configured passcode; on match set the gate cookie + redirect to `/`; on
 *     mismatch re-show the page with an error (no lockout).
 * Returns 405 for any other method.
 */
export function handleGate(method: string, body: Record<string, unknown>): GateResponse {
  if (method === 'GET') return unlockPageResponse(false);
  if (method !== 'POST') return { status: 405, body: { error: 'Method not allowed' } };

  const supplied = submittedPasscode(body);
  if (supplied !== '' && safeEqual(supplied, passcode())) {
    return { status: 200, body: { ok: true }, setCookie: setGateCookieHeader(), redirect: '/' };
  }
  return unlockPageResponse(true);
}
