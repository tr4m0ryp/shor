// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Dashboard users API (multi-user surface, ADR-044).
 *
 * `GET /users` lists the caller-tenant's users (and marks the signed-in one) so
 * the dashboard can show who shares the tenant. Tenant-scoped via `gate()`: a
 * caller only ever sees its own tenant's users.
 */

import { userRepo } from '../../db/repositories/index.js';
import type { ApiResponse } from '../router.js';
import { gate, ok, serverError } from './auth-util.js';

/** `GET /users` — list the caller-tenant's users; flag the current principal. */
export async function listUsers(cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const users = await userRepo.listByTenant(g.tenantId);
    const annotated = users.map((u) => ({ ...u, isCurrent: u.id === g.principal.uid }));
    return ok({ users: annotated, currentUserId: g.principal.uid });
  } catch (err) {
    return serverError(err);
  }
}
