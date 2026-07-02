// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Tenant scoping (ADR-044).
 *
 * Row-level tenant scoping is enforced at the app layer: every authenticated
 * request must carry a `tenantId` claim, and every tenant-owned resource the
 * request touches must match it. These helpers are the single choke point —
 * route handlers call `scopedTenantId(principal)` to obtain the tenant id to
 * pass to the repositories, and `assertTenant(principal, resourceTenantId)` to
 * reject any cross-tenant access before a repo call.
 */

import type { TenantId } from '../domain/types.js';
import type { Principal } from './middleware.js';

export class TenantScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TenantScopeError';
  }
}

/**
 * Return the tenant id the request is scoped to (the verified `tenantId` claim).
 * Throws `TenantScopeError` when the principal has no tenant — every
 * authenticated request MUST be tenant-scoped.
 */
export function scopedTenantId(principal: Principal): TenantId {
  if (!principal.tenantId) {
    throw new TenantScopeError('request principal has no tenant id');
  }
  return principal.tenantId;
}

/**
 * Assert that a resource belongs to the principal's tenant. Use before handing
 * a caller-supplied `tenantId` (path/body) to a repository, so a tenant can
 * never name another tenant's tenant id. Throws on mismatch.
 */
export function assertTenant(principal: Principal, resourceTenantId: TenantId): TenantId {
  const scoped = scopedTenantId(principal);
  if (resourceTenantId !== scoped) {
    throw new TenantScopeError('tenant mismatch: cross-tenant access denied');
  }
  return scoped;
}
