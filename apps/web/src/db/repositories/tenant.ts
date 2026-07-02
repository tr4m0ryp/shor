// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Tenant repository (LAUNCH-SPEC §4.3).
 *
 * The tenant is the root of the project model and the unit of row-level scoping
 * (ADR-044). All other repositories take a `tenantId` and scope every query by
 * it; this repo is where tenants are created and looked up.
 */

import { query } from '../../cloud/pg.js';
import type { NewTenant, Tenant, TenantId } from '../../domain/types.js';
import { type TenantRow, toTenant } from './rows.js';

export const tenantRepo = {
  async create(input: NewTenant): Promise<Tenant> {
    const { rows } = await query<TenantRow>(
      `INSERT INTO tenant (org_name, idp_tenant_id, plan)
			 VALUES ($1, $2, COALESCE($3, 'free'))
			 RETURNING *`,
      [input.orgName, input.idpTenantId, input.plan ?? null],
    );
    return toTenant(rows[0] as TenantRow);
  },

  async findById(id: TenantId): Promise<Tenant | null> {
    const { rows } = await query<TenantRow>('SELECT * FROM tenant WHERE id = $1', [id]);
    return rows[0] ? toTenant(rows[0]) : null;
  },

  /** Resolve a tenant by its Identity Platform tenant id (login path). */
  async findByIdpTenantId(idpTenantId: string): Promise<Tenant | null> {
    const { rows } = await query<TenantRow>('SELECT * FROM tenant WHERE idp_tenant_id = $1', [idpTenantId]);
    return rows[0] ? toTenant(rows[0]) : null;
  },

  async list(): Promise<Tenant[]> {
    const { rows } = await query<TenantRow>('SELECT * FROM tenant ORDER BY created_at DESC');
    return rows.map(toTenant);
  },

  async delete(id: TenantId): Promise<void> {
    await query('DELETE FROM tenant WHERE id = $1', [id]);
  },
};
