/**
 * AttackSurface repository (LAUNCH-SPEC §4.3).
 *
 * Stores storron's attack-surface scenario / kill-chain document as JSONB, one
 * row per scan. Hangs off `scan`; queries join through `scan` → `project` and
 * filter by `tenant_id` for tenant scoping.
 */

import { query } from '../../cloud/pg.js';
import type { AttackSurface, AttackSurfaceId, NewAttackSurface, ScanId, TenantId } from '../../domain/types.js';
import { type AttackSurfaceRow, toAttackSurface } from './rows.js';

const SELECT_SCOPED = `
	SELECT a.* FROM attack_surface a
	JOIN scan s ON s.id = a.scan_id
	JOIN project p ON p.id = s.project_id
	WHERE p.tenant_id = $1`;

export const attackSurfaceRepo = {
  async create(input: NewAttackSurface): Promise<AttackSurface> {
    const { rows } = await query<AttackSurfaceRow>(
      `INSERT INTO attack_surface (scan_id, data)
			 VALUES ($1, $2)
			 RETURNING *`,
      [input.scanId, input.data],
    );
    return toAttackSurface(rows[0] as AttackSurfaceRow);
  },

  async findById(tenantId: TenantId, id: AttackSurfaceId): Promise<AttackSurface | null> {
    const { rows } = await query<AttackSurfaceRow>(`${SELECT_SCOPED} AND a.id = $2`, [tenantId, id]);
    return rows[0] ? toAttackSurface(rows[0]) : null;
  },

  async findByScan(tenantId: TenantId, scanId: ScanId): Promise<AttackSurface | null> {
    const { rows } = await query<AttackSurfaceRow>(`${SELECT_SCOPED} AND a.scan_id = $2`, [tenantId, scanId]);
    return rows[0] ? toAttackSurface(rows[0]) : null;
  },
};
