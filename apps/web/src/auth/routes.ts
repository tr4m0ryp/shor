/**
 * Auth routes (ADR-016 / ADR-042 / ADR-043 / ADR-044).
 *
 *   POST /auth/session  — body `{ idToken }`: verify the Identity Platform ID
 *                         token, upsert the tenant + user via the repositories,
 *                         mint the server session cookie, return the principal.
 *   POST /auth/logout   — clear the session cookie.
 *   GET  /auth/me       — return the current principal from the session cookie.
 *
 * Handlers are pure: they take the request inputs and return a response
 * envelope (`{ status, body, setCookie? }`); the framework-less server entry
 * writes the status/JSON/`Set-Cookie`. This mirrors storron's `apiRouter`
 * pure-function shape (`apps/web/src/api/router.ts`).
 */

import { verifyIdToken } from '../cloud/identity.js';
import { tenantRepo } from '../db/repositories/tenant.js';
import { userRepo } from '../db/repositories/user.js';
import type { Tenant, User } from '../domain/types.js';
import { authenticate } from './middleware.js';
import { buildClearCookie, buildSessionCookie, mintSession, type SessionClaims } from './session.js';

/** Response envelope for an auth route — JSON body plus optional `Set-Cookie`. */
export interface AuthRouteResponse {
  readonly status: number;
  readonly body: Record<string, unknown>;
  /** A `Set-Cookie` header value to emit, when the route sets/clears the cookie. */
  readonly setCookie?: string;
}

function principalBody(claims: SessionClaims): Record<string, unknown> {
  return { uid: claims.uid, tenantId: claims.tenantId, role: claims.role, org: claims.org };
}

/**
 * `POST /auth/session` — exchange a verified Identity Platform ID token for a
 * server session cookie. Upserts the tenant (by IdP tenant id) and user (by
 * email within the tenant) so first-login provisions rows idempotently.
 */
export async function handleSessionLogin(body: Record<string, unknown>): Promise<AuthRouteResponse> {
  const idToken = body.idToken;
  if (typeof idToken !== 'string' || idToken.length === 0) {
    return { status: 400, body: { error: 'idToken is required' } };
  }

  let verified: Awaited<ReturnType<typeof verifyIdToken>>;
  try {
    verified = await verifyIdToken(idToken);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { status: 401, body: { error: msg } };
  }

  let tenant: Tenant;
  let user: User;
  try {
    tenant = await upsertTenant(verified.tenantId);
    user = await upsertUser(tenant.id, verified.email, verified.role);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { status: 500, body: { error: msg } };
  }

  // The session is keyed by our DB user/tenant ids (not the raw IdP uid/tenant),
  // so all downstream tenant scoping uses the same ids the repositories use.
  const claims: SessionClaims = {
    uid: user.id,
    tenantId: tenant.id,
    role: user.role,
    org: tenant.orgName,
  };
  const token = mintSession(claims);
  return { status: 200, body: { user: principalBody(claims) }, setCookie: buildSessionCookie(token) };
}

/** `POST /auth/logout` — clear the session cookie. Always succeeds. */
export function handleLogout(): AuthRouteResponse {
  return { status: 200, body: { ok: true }, setCookie: buildClearCookie() };
}

/** `GET /auth/me` — return the current principal, or `401` when unauthenticated. */
export function handleMe(cookieHeader: string | undefined): AuthRouteResponse {
  const auth = authenticate(cookieHeader);
  if (!auth.ok) {
    return { status: auth.status, body: { error: auth.error } };
  }
  return { status: 200, body: { user: principalBody(auth.principal) } };
}

/**
 * Find-or-create the tenant for a verified IdP tenant id. The IdP tenant id is
 * the org's identity; `orgName` defaults to it until set elsewhere.
 */
async function upsertTenant(idpTenantId: string): Promise<Tenant> {
  const existing = await tenantRepo.findByIdpTenantId(idpTenantId);
  if (existing) return existing;
  // `plan` is server-defaulted by the repo (SQL COALESCE → 'free'); pass it
  // explicitly to satisfy exactOptionalPropertyTypes on `NewTenant`.
  return tenantRepo.create({ orgName: idpTenantId, idpTenantId, plan: 'free' });
}

/**
 * Find-or-create the user within a tenant by email. On an existing user the IdP
 * `role` claim is treated as authoritative and synced when it drifts.
 */
async function upsertUser(tenantId: string, email: string, role: User['role']): Promise<User> {
  const existing = await userRepo.findByEmail(tenantId, email);
  if (!existing) {
    return userRepo.create({ tenantId, email, role });
  }
  if (existing.role !== role) {
    const updated = await userRepo.updateRole(tenantId, existing.id, role);
    if (updated) return updated;
  }
  return existing;
}
