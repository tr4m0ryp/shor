/**
 * Dashboard auth/tenant-scope gate (ADR-044).
 *
 * Every dashboard data route is authenticated and tenant-scoped. These helpers
 * are the shared choke point: `gate(cookieHeader)` verifies the session cookie
 * and returns either the `Principal` (with its scoped `tenantId`) or a ready-made
 * error response envelope the dispatcher can return verbatim. Keeping the gate in
 * one place means no route can forget to scope (it cannot reach a repository
 * without a `tenantId`).
 */

import { type Principal, requireAuth, scopedTenantId } from '../../auth/index.js';
import type { TenantId } from '../../domain/types.js';
import type { ApiResponse } from '../router.js';

/** Result of the gate: success carries the principal + its scoped tenant id. */
export type GateResult =
  | { readonly ok: true; readonly principal: Principal; readonly tenantId: TenantId }
  | { readonly ok: false; readonly response: ApiResponse };

/**
 * Authenticate a request and resolve its tenant scope. On failure returns a
 * `{ ok: false, response }` whose `response` is the HTTP envelope to return
 * (401 unauthenticated / 403 forbidden). On success returns the principal and
 * the verified `tenantId` claim every repository call must be scoped by.
 */
export function gate(cookieHeader: string | undefined): GateResult {
  const auth = requireAuth(cookieHeader);
  if (!auth.ok) {
    return { ok: false, response: { status: auth.status, body: { error: auth.error } } };
  }
  const tenantId = scopedTenantId(auth.principal);
  return { ok: true, principal: auth.principal, tenantId };
}

/** Convenience JSON envelopes shared across dashboard handlers. */
export const ok = (body: Record<string, unknown>): ApiResponse => ({ status: 200, body });
export const created = (body: Record<string, unknown>): ApiResponse => ({ status: 201, body });
export const badRequest = (error: string): ApiResponse => ({ status: 400, body: { error } });
export const notFound = (error = 'Not found'): ApiResponse => ({ status: 404, body: { error } });
export const methodNotAllowed: ApiResponse = { status: 405, body: { error: 'Method not allowed' } };

/** Map a thrown error to a 500 envelope (used by route try/catch wrappers). */
export function serverError(err: unknown): ApiResponse {
  const msg = err instanceof Error ? err.message : String(err);
  return { status: 500, body: { error: msg } };
}
