// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Multi-tenant auth — public surface (Phase 3, ADR-016/042/043/044).
 *
 * Server-minted session cookie over a verified Identity Platform ID token,
 * RBAC guards, tenant scoping, and the `/auth/*` route handlers. The IdP token
 * never reaches the browser; only the HTTP-only signed cookie does.
 */

export { ensureDevSession } from './dev-session.js';
export type { AuthResult, Principal } from './middleware.js';
export { authenticate, requireAuth, requireMinRole, requireRole } from './middleware.js';
export type { AuthRouteResponse } from './routes.js';
export { handleLogout, handleMe, handleSessionLogin } from './routes.js';
export type { SessionClaims, SessionCookieOptions, SessionPayload } from './session.js';
export {
  buildClearCookie,
  buildSessionCookie,
  mintSession,
  readSessionCookie,
  SessionError,
  verifySession,
} from './session.js';
export { assertTenant, scopedTenantId, TenantScopeError } from './tenant-scope.js';
