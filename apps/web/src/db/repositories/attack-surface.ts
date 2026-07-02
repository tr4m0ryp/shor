// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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

  /**
   * Upsert the scan's attack-surface document, last-write-wins. The worker posts
   * the attack surface on every sink emission: the engine's local synthesis lands
   * first (during the run), then the final `completed` post carries the richer
   * Sinas/Opus synthesis. A create-if-absent pins whichever doc arrives first (the
   * engine one, whose schema the dashboard does not even render) and silently
   * drops the Opus rewrite — so always reflect the latest. `scan_id` has a single
   * writer here, so UPDATE-then-INSERT suffices without an ON CONFLICT target.
   */
  async upsert(input: NewAttackSurface): Promise<AttackSurface> {
    const updated = await query<AttackSurfaceRow>(
      `UPDATE attack_surface SET data = $2 WHERE scan_id = $1 RETURNING *`,
      [input.scanId, input.data],
    );
    if (updated.rows[0]) return toAttackSurface(updated.rows[0]);
    return this.create(input);
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
