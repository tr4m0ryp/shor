// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Server-minted session cookie (ADR-043).
 *
 * Identity Platform issues a ~1h ID-token JWT; we verify it server-side
 * (`cloud/identity.verifyIdToken`) and then mint our OWN session cookie so the
 * IdP token never reaches browser JS. The cookie is an HMAC-SHA256-signed,
 * base64url-encoded `{uid, tenantId, role, org, iat, exp}` payload — no external
 * JWT library, just Node's built-in `crypto`. The signing secret comes from
 * `getConfig()` (`SESSION_SIGNING_SECRET`), and the cookie is set HTTP-only,
 * Secure, SameSite=Lax with a configurable TTL (`SESSION_TTL_SECONDS`).
 *
 * Format: `<base64url(payloadJson)>.<base64url(hmac)>` — a compact, self-
 * contained, stateless token verified with a constant-time signature compare.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { getConfig } from '../config.js';
import type { TenantId, UserId, UserRole } from '../domain/types.js';
import { USER_ROLES } from '../domain/types.js';

/** Claims carried by the signed session cookie (ADR-043: `{tenantId, role, org}`). */
export interface SessionClaims {
  readonly uid: UserId;
  readonly tenantId: TenantId;
  readonly role: UserRole;
  /** Org name (display label for the tenant). */
  readonly org: string;
}

/** Decoded session token = claims plus issued-at / expiry (epoch seconds). */
export interface SessionPayload extends SessionClaims {
  /** Issued-at, epoch seconds. */
  readonly iat: number;
  /** Expiry, epoch seconds. */
  readonly exp: number;
}

export class SessionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SessionError';
  }
}

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

function signingSecret(): string {
  const secret = getConfig().session.signingSecret;
  if (!secret) {
    throw new SessionError('SESSION_SIGNING_SECRET is not configured');
  }
  return secret;
}

function sign(encodedPayload: string): string {
  return createHmac('sha256', signingSecret()).update(encodedPayload).digest('base64url');
}

/**
 * Mint a signed session token from verified claims. The TTL defaults to
 * `SESSION_TTL_SECONDS` from config; pass `ttlSeconds` to override.
 */
export function mintSession(claims: SessionClaims, ttlSeconds?: number): string {
  const ttl = ttlSeconds ?? getConfig().session.ttlSeconds;
  const iat = Math.floor(Date.now() / 1000);
  const payload: SessionPayload = { ...claims, iat, exp: iat + ttl };
  const encodedPayload = base64url(JSON.stringify(payload));
  return `${encodedPayload}.${sign(encodedPayload)}`;
}

/**
 * Verify a session token: checks the HMAC signature (constant-time) and the
 * expiry, and validates the decoded shape. Throws `SessionError` on any failure.
 */
export function verifySession(token: string): SessionPayload {
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) {
    throw new SessionError('malformed session token');
  }
  const encodedPayload = token.slice(0, dot);
  const providedSig = token.slice(dot + 1);

  const expectedSig = sign(encodedPayload);
  const provided = Buffer.from(providedSig);
  const expected = Buffer.from(expectedSig);
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    throw new SessionError('bad session signature');
  }

  const payload = decodePayload(encodedPayload);
  if (payload.exp <= Math.floor(Date.now() / 1000)) {
    throw new SessionError('session expired');
  }
  return payload;
}

function decodePayload(encodedPayload: string): SessionPayload {
  let raw: unknown;
  try {
    raw = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
  } catch {
    throw new SessionError('undecodable session payload');
  }
  if (typeof raw !== 'object' || raw === null) {
    throw new SessionError('invalid session payload');
  }
  const obj = raw as Record<string, unknown>;
  const { uid, tenantId, org } = obj;
  const role = obj.role;
  const iat = obj.iat;
  const exp = obj.exp;
  if (
    typeof uid !== 'string' ||
    typeof tenantId !== 'string' ||
    typeof org !== 'string' ||
    typeof role !== 'string' ||
    !(USER_ROLES as readonly string[]).includes(role) ||
    typeof iat !== 'number' ||
    typeof exp !== 'number'
  ) {
    throw new SessionError('invalid session claims');
  }
  return { uid, tenantId, org, role: role as UserRole, iat, exp };
}

/** Cookie attributes for the minted session (ADR-043). */
export interface SessionCookieOptions {
  /** Override the Secure flag (default: on in production). */
  readonly secure?: boolean;
}

/**
 * Build the `Set-Cookie` header value carrying a freshly minted session token.
 * HTTP-only + SameSite=Lax always; Secure in production (and when forced).
 */
export function buildSessionCookie(token: string, options: SessionCookieOptions = {}): string {
  const cfg = getConfig();
  const secure = options.secure ?? cfg.env === 'production';
  const parts = [
    `${cfg.session.cookieName}=${token}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${cfg.session.ttlSeconds}`,
  ];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

/** Build the `Set-Cookie` header value that clears the session (logout). */
export function buildClearCookie(options: SessionCookieOptions = {}): string {
  const cfg = getConfig();
  const secure = options.secure ?? cfg.env === 'production';
  const parts = [`${cfg.session.cookieName}=`, 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=0'];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

/** Read the session token from a raw `Cookie` request header (or `null`). */
export function readSessionCookie(cookieHeader: string | undefined): string | null {
  if (!cookieHeader) return null;
  const name = getConfig().session.cookieName;
  for (const pair of cookieHeader.split(';')) {
    const eq = pair.indexOf('=');
    if (eq < 0) continue;
    if (pair.slice(0, eq).trim() === name) {
      return pair.slice(eq + 1).trim() || null;
    }
  }
  return null;
}
