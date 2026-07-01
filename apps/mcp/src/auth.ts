/**
 * MCP transport auth — isolated so bearer ↔ OAuth is a SINGLE swap.
 *
 * Claude Code connects with a static bearer today; the claude.ai web connector
 * expects OAuth. Both reduce to one question the transport asks per request: "is
 * this caller allowed?". That question is answered by an `Authenticator`, chosen
 * by `MCP_AUTH_MODE`. Swapping to OAuth means implementing `oauthAuthenticator`
 * (verify the access token, publish protected-resource metadata) — the tools, the
 * Shor client, and the HTTP plumbing do not change.
 */

import { timingSafeEqual } from 'node:crypto';
import { getConfig } from './config.js';

export interface AuthResult {
  readonly ok: boolean;
  /** HTTP status to return on failure (401/403). */
  readonly status?: number;
  /** `WWW-Authenticate` value to return on 401 (OAuth discovery hook). */
  readonly wwwAuthenticate?: string;
  readonly message?: string;
}

export interface Authenticator {
  authenticate(authHeader: string | undefined): AuthResult;
}

function parseBearer(authHeader: string | undefined): string | undefined {
  if (!authHeader) return undefined;
  const m = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
  return m ? m[1] : undefined;
}

/** Constant-time string compare that tolerates unequal lengths without leaking them. */
function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) {
    // Compare against self so timing does not depend on the length mismatch.
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}

/** Static-bearer authenticator (Claude Code, and any header-bearer client). */
export const bearerAuthenticator: Authenticator = {
  authenticate(authHeader) {
    const { bearerToken } = getConfig();
    // Empty configured bearer disables the connector rather than allowing all.
    if (bearerToken === '') return { ok: false, status: 401, message: 'connector auth not configured' };
    const presented = parseBearer(authHeader);
    if (presented !== undefined && safeEqual(presented, bearerToken)) return { ok: true };
    return { ok: false, status: 401, wwwAuthenticate: 'Bearer', message: 'invalid or missing bearer token' };
  },
};

/**
 * OAuth authenticator seam for the claude.ai web connector. Not yet wired: it
 * fails closed and advertises where the authorization server WILL live via
 * `WWW-Authenticate`, so turning it on is implementing this one method plus the
 * `/.well-known/oauth-protected-resource` document — nothing else moves.
 */
export const oauthAuthenticator: Authenticator = {
  authenticate() {
    return {
      ok: false,
      status: 401,
      wwwAuthenticate: 'Bearer resource_metadata="/.well-known/oauth-protected-resource"',
      message: 'OAuth is not yet enabled on this connector',
    };
  },
};

/** Select the authenticator for the configured mode. */
export function getAuthenticator(): Authenticator {
  return getConfig().authMode === 'oauth' ? oauthAuthenticator : bearerAuthenticator;
}
