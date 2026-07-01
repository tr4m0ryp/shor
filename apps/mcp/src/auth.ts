/**
 * MCP transport auth — isolated so bearer ↔ OAuth is a SINGLE swap.
 *
 * Claude Code connects with a static bearer; the claude.ai web connector uses
 * OAuth. Both reduce to one question the transport asks per request: "is this
 * caller allowed?". That question is answered by an `Authenticator`, chosen by
 * `MCP_AUTH_MODE`.
 *
 *   bearer — constant-time compare against `MCP_BEARER_TOKEN`.
 *   oauth  — WorkOS AuthKit is the authorization server; this connector is a pure
 *            OAuth 2.0 RESOURCE server (RFC 9728). It verifies AuthKit-issued JWT
 *            access tokens against AuthKit's JWKS (signature + issuer + expiry)
 *            and advertises AuthKit for discovery via protected-resource metadata.
 *            No WorkOS client secret lives here — claude.ai registers with AuthKit
 *            directly (Dynamic Client Registration) and only presents the token.
 */

import { timingSafeEqual } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
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
  authenticate(authHeader: string | undefined): Promise<AuthResult>;
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
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}

// ─────────────────────────────── bearer ────────────────────────────────────

/** Static-bearer authenticator (Claude Code, and any header-bearer client). */
export const bearerAuthenticator: Authenticator = {
  authenticate(authHeader) {
    const { bearerToken } = getConfig();
    if (bearerToken === '') return Promise.resolve({ ok: false, status: 401, message: 'connector auth not configured' });
    const presented = parseBearer(authHeader);
    if (presented !== undefined && safeEqual(presented, bearerToken)) return Promise.resolve({ ok: true });
    return Promise.resolve({ ok: false, status: 401, wwwAuthenticate: 'Bearer', message: 'invalid or missing bearer token' });
  },
};

// ────────────────────────── oauth (WorkOS AuthKit) ─────────────────────────

/** The OAuth 2.0 resource identifier this connector protects (`${base}/mcp`). */
export function resourceUrl(): string {
  return `${getConfig().baseUrl}/mcp`;
}

/** Absolute URL of this connector's protected-resource metadata document. */
export function resourceMetadataUrl(): string {
  return `${getConfig().baseUrl}/.well-known/oauth-protected-resource`;
}

/**
 * OAuth 2.0 Protected Resource Metadata (RFC 9728) — tells a client which
 * authorization server to use (WorkOS AuthKit) for THIS resource. Served
 * unauthenticated; claude.ai reads it, then does DCR + login with AuthKit.
 */
export function protectedResourceMetadata(): Record<string, unknown> {
  const { workosAuthkitDomain } = getConfig();
  return {
    resource: resourceUrl(),
    authorization_servers: [workosAuthkitDomain],
    bearer_methods_supported: ['header'],
    scopes_supported: [] as string[],
  };
}

// Cache the JWKS fetcher per process (jose caches keys and refreshes on rotation).
let jwks: ReturnType<typeof createRemoteJWKSet> | undefined;
function authkitJwks(domain: string) {
  if (!jwks) jwks = createRemoteJWKSet(new URL(`${domain}/oauth2/jwks`));
  return jwks;
}

/**
 * WorkOS AuthKit resource-server authenticator: verify the presented JWT is a
 * live AuthKit-issued token (signature via AuthKit JWKS, `iss` = the AuthKit
 * domain, unexpired). On failure, advertise where to authenticate via
 * `WWW-Authenticate: Bearer resource_metadata=…` so the client starts the flow.
 */
export const workosAuthenticator: Authenticator = {
  async authenticate(authHeader) {
    const { workosAuthkitDomain, baseUrl } = getConfig();
    const challenge = `Bearer resource_metadata="${resourceMetadataUrl()}"`;
    if (!workosAuthkitDomain || !baseUrl) {
      return { ok: false, status: 500, message: 'oauth mode misconfigured: WORKOS_AUTHKIT_DOMAIN + MCP_BASE_URL required' };
    }
    const token = parseBearer(authHeader);
    if (!token) return { ok: false, status: 401, wwwAuthenticate: challenge, message: 'missing bearer token' };
    try {
      await jwtVerify(token, authkitJwks(workosAuthkitDomain), { issuer: workosAuthkitDomain });
      return { ok: true };
    } catch (err) {
      return {
        ok: false,
        status: 401,
        wwwAuthenticate: challenge,
        message: `invalid token: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  },
};

/** Select the authenticator for the configured mode. */
export function getAuthenticator(): Authenticator {
  return getConfig().authMode === 'oauth' ? workosAuthenticator : bearerAuthenticator;
}

/** True when OAuth mode is active (the transport then serves resource metadata). */
export function isOAuthMode(): boolean {
  return getConfig().authMode === 'oauth';
}
