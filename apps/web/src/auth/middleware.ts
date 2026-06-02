/**
 * Auth middleware (ADR-043 / ADR-044).
 *
 * The web server is framework-less (Node `http` + a pure-function router, like
 * storron), so "middleware" here is a set of pure helpers rather than
 * Express-style `(req, res, next)`. A handler reads the request's `Cookie`
 * header, calls `authenticate()` to verify the session and attach the
 * principal, then gates with `requireAuth` / `requireRole(...)`.
 *
 * Each guard returns a discriminated `AuthResult`: `{ ok: true, principal }` on
 * success or `{ ok: false, status, error }` on rejection, so the router can turn
 * a failure straight into an HTTP response without throwing.
 */

import type { TenantId, UserId, UserRole } from '../domain/types.js';
import { USER_ROLES } from '../domain/types.js';
import { readSessionCookie, SessionError, type SessionPayload, verifySession } from './session.js';

/** The authenticated caller attached to a request after `authenticate()`. */
export interface Principal {
  readonly uid: UserId;
  readonly tenantId: TenantId;
  readonly role: UserRole;
  readonly org: string;
}

/** Result of an auth guard: success carries the principal, failure an HTTP code. */
export type AuthResult =
  | { readonly ok: true; readonly principal: Principal }
  | { readonly ok: false; readonly status: 401 | 403; readonly error: string };

function toPrincipal(payload: SessionPayload): Principal {
  return { uid: payload.uid, tenantId: payload.tenantId, role: payload.role, org: payload.org };
}

/**
 * Verify the session cookie on a request and resolve the principal.
 * Returns `401` when the cookie is missing, malformed, expired, or unsigned.
 */
export function authenticate(cookieHeader: string | undefined): AuthResult {
  const token = readSessionCookie(cookieHeader);
  if (!token) {
    return { ok: false, status: 401, error: 'no session' };
  }
  try {
    return { ok: true, principal: toPrincipal(verifySession(token)) };
  } catch (err) {
    if (err instanceof SessionError) {
      return { ok: false, status: 401, error: err.message };
    }
    throw err;
  }
}

/**
 * Require an authenticated request. Thin alias over `authenticate()` that names
 * the intent at call sites guarding protected routes.
 */
export function requireAuth(cookieHeader: string | undefined): AuthResult {
  return authenticate(cookieHeader);
}

/** Rank for role comparison — higher index = more privilege. */
const ROLE_RANK: Readonly<Record<UserRole, number>> = {
  viewer: 0,
  member: 1,
  admin: 2,
  owner: 3,
};

/**
 * Require an authenticated request whose role is in `roles` (RBAC, ADR-044).
 * Authenticates first (→ `401`), then checks membership (→ `403`). Roles are
 * matched exactly; use `requireMinRole` for hierarchical "at least" checks.
 */
export function requireRole(...roles: readonly UserRole[]): (cookieHeader: string | undefined) => AuthResult {
  const allowed = new Set<UserRole>(roles.length ? roles : (USER_ROLES as readonly UserRole[]));
  return (cookieHeader) => {
    const auth = authenticate(cookieHeader);
    if (!auth.ok) return auth;
    if (!allowed.has(auth.principal.role)) {
      return { ok: false, status: 403, error: `role ${auth.principal.role} not permitted` };
    }
    return auth;
  };
}

/**
 * Require an authenticated request whose role is at least `min` by privilege
 * (`viewer < member < admin < owner`). Convenience over `requireRole` for the
 * common "this and anything above" gate.
 */
export function requireMinRole(min: UserRole): (cookieHeader: string | undefined) => AuthResult {
  const threshold = ROLE_RANK[min];
  return (cookieHeader) => {
    const auth = authenticate(cookieHeader);
    if (!auth.ok) return auth;
    if (ROLE_RANK[auth.principal.role] < threshold) {
      return { ok: false, status: 403, error: `role ${auth.principal.role} below required ${min}` };
    }
    return auth;
  };
}
