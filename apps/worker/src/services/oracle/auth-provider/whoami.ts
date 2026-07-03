// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * whoami / identity-echo runner (T9, F3/F4). Proves a replay really fires AS the
 * intended principal (not silently logged out) BEFORE the differential is trusted
 * — run for EVERY authenticated identity, closing Ali's cookie-only gap.
 *
 * Two echo paths: a `networkEcho` (fetch a whoami endpoint as the identity and
 * assert the expected principal appears in the body) and a `jwtClaimEcho` (decode
 * the bearer JWT's claims locally — no round-trip — and assert the principal).
 * Both fail-open: anything short of a positive match is `inconclusive_infra`,
 * NEVER a `blocked` refutation (a flaky whoami must not disprove a real bug).
 */

import type { EchoContext, EchoResult, ExpectedPrincipal } from './types.js';

const CONFIRMED: EchoResult = { status: 'confirmed', reason: 'matched' };
function inconclusive(reason: EchoResult['reason']): EchoResult {
  return { status: 'inconclusive_infra', reason };
}

/** Cap the whoami body we read so a huge response cannot exhaust memory. */
const MAX_BODY_CHARS = 32 * 1024;

/** Non-secret principal hints (label + role) — safe to include in logs. */
export function principalHints(p: ExpectedPrincipal): string[] {
  return [p.label, p.role].filter((t): t is string => typeof t === 'string' && t.trim() !== '');
}

/**
 * All tokens the echo may assert against — non-secret hints PLUS any runtime token
 * (username/id). Used to build the assertion in-memory ONLY; never returned/logged.
 */
function assertionTokens(p: ExpectedPrincipal): string[] {
  const runtime = (p.runtimeTokens ?? []).filter((t) => typeof t === 'string' && t.trim() !== '');
  // A bare directory label like 'identity-member' rarely appears verbatim in a
  // whoami body, so it is a weak assertion on its own; runtime tokens (when 008
  // supplies them) are what make the echo decisive.
  return [...runtime, ...principalHints(p)];
}

/**
 * Fetch a whoami endpoint as the identity and assert the principal appears in the
 * body. No endpoint / no assertable token / transport failure / a 401-403 (not
 * logged in) / a body lacking every token all resolve to `inconclusive_infra`.
 */
export async function networkEcho(
  endpoint: string | undefined,
  headers: Readonly<Record<string, string>>,
  principal: ExpectedPrincipal,
  ctx: EchoContext,
): Promise<EchoResult> {
  if (!endpoint) return inconclusive('no_endpoint');
  const tokens = assertionTokens(principal);
  if (tokens.length === 0) return inconclusive('no_endpoint');

  try {
    ctx.assertAllowed(endpoint);
  } catch {
    return inconclusive('unreachable');
  }

  const controller = new AbortController();
  const timer = ctx.timeoutMs > 0 ? setTimeout(() => controller.abort(), ctx.timeoutMs) : undefined;
  let res: Response;
  try {
    res = await ctx.fetchImpl(endpoint, { method: 'GET', headers: { ...headers }, signal: controller.signal });
  } catch {
    return inconclusive('error');
  } finally {
    if (timer) clearTimeout(timer);
  }

  // A whoami that rejects the session (401/403) means we are NOT the principal —
  // a mismatch, but still inconclusive (never a blocked refutation of the finding).
  if (res.status === 401 || res.status === 403) return inconclusive('mismatch');
  if (!res.ok) return inconclusive('unreachable');

  let body = '';
  try {
    body = (await res.text()).slice(0, MAX_BODY_CHARS);
  } catch {
    return inconclusive('error');
  }
  return tokens.some((t) => body.includes(t)) ? CONFIRMED : inconclusive('mismatch');
}

/** base64url-decode a JWT segment to UTF-8; '' on any malformed input. */
function b64urlDecode(segment: string): string {
  try {
    const b64 = segment.replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(b64, 'base64').toString('utf8');
  } catch {
    return '';
  }
}

/**
 * Decode a JWT's claim set WITHOUT verifying its signature. The echo asserts WHO a
 * token claims to be (identity), not that the token is trusted — signature checks
 * are the target's job, not the oracle's. `undefined` when the token is not a JWT.
 */
export function decodeJwtClaims(token: string): Record<string, unknown> | undefined {
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[1]) return undefined;
  const json = b64urlDecode(parts[1]);
  if (json === '') return undefined;
  try {
    const parsed: unknown = JSON.parse(json);
    return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

/** Claims that conventionally carry the principal identity. */
const PRINCIPAL_CLAIMS = ['sub', 'preferred_username', 'username', 'email', 'upn', 'name'] as const;

/**
 * Local (no-network) echo for bearer/OIDC identities: decode the JWT and assert a
 * principal claim matches an expected token. Not a JWT, or no matching claim →
 * `inconclusive_infra` (the caller may then fall back to a `networkEcho`).
 */
export function jwtClaimEcho(token: string, principal: ExpectedPrincipal): EchoResult {
  const claims = decodeJwtClaims(token);
  if (!claims) return inconclusive('no_endpoint');
  const tokens = assertionTokens(principal);
  if (tokens.length === 0) return inconclusive('no_endpoint');
  for (const claim of PRINCIPAL_CLAIMS) {
    const v = claims[claim];
    if (typeof v === 'string' && tokens.some((t) => v === t || v.includes(t))) return CONFIRMED;
    if (typeof v === 'number' && tokens.some((t) => String(v) === t)) return CONFIRMED;
  }
  return inconclusive('mismatch');
}
