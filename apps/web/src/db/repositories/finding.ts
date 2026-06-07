/**
 * Finding repository (LAUNCH-SPEC §4.3 + §6.1, ADR-030/031/033).
 *
 * Findings are stored as JSONB (`data`) in storron's shape, keyed by the stable
 * `fingerprint` for idempotent re-ingest. Hangs off `scan`; queries join through
 * `scan` → `project` and filter by `tenant_id` for tenant scoping.
 */

import { query } from '../../cloud/pg.js';
import type { Finding, FindingId, FindingStatus, NewFinding, ScanId, TenantId } from '../../domain/types.js';
import { type FindingRow, toFinding } from './rows.js';

const SELECT_SCOPED = `
	SELECT f.* FROM finding f
	JOIN scan s ON s.id = f.scan_id
	JOIN project p ON p.id = s.project_id
	WHERE p.tenant_id = $1`;

export const findingRepo = {
  async create(input: NewFinding): Promise<Finding> {
    const { rows } = await query<FindingRow>(
      `INSERT INTO finding (scan_id, fingerprint, data, status)
			 VALUES ($1, $2, $3, COALESCE($4, 'new'))
			 RETURNING *`,
      [input.scanId, input.fingerprint, input.data, input.status ?? null],
    );
    return toFinding(rows[0] as FindingRow);
  },

  async findById(tenantId: TenantId, id: FindingId): Promise<Finding | null> {
    const { rows } = await query<FindingRow>(`${SELECT_SCOPED} AND f.id = $2`, [tenantId, id]);
    return rows[0] ? toFinding(rows[0]) : null;
  },

  async listByScan(tenantId: TenantId, scanId: ScanId): Promise<Finding[]> {
    const { rows } = await query<FindingRow>(`${SELECT_SCOPED} AND f.scan_id = $2 ORDER BY f.created_at`, [
      tenantId,
      scanId,
    ]);
    return rows.map(toFinding);
  },

  /** Look up a finding by its stable fingerprint within one scan (sink dedup path). */
  async findByFingerprint(tenantId: TenantId, scanId: ScanId, fingerprint: string): Promise<Finding | null> {
    const { rows } = await query<FindingRow>(`${SELECT_SCOPED} AND f.scan_id = $2 AND f.fingerprint = $3`, [
      tenantId,
      scanId,
      fingerprint,
    ]);
    return rows[0] ? toFinding(rows[0]) : null;
  },

  /**
   * Refresh an existing finding's `data` JSONB in place (idempotent re-ingest of
   * the same fingerprint within a scan). The worker posts findings incrementally
   * as agents finish — the first post lands the analysis hypothesis (`queued` →
   * `firm`), and later posts carry the live-exploitation disposition
   * (`exploited` → `confirmed`) and improved prose. Without this update the first
   * write froze every finding at `firm`. Optionally refreshes the `status` column
   * (kept as-is when `status` is null/omitted).
   */
  async updateData(
    tenantId: TenantId,
    id: FindingId,
    data: NewFinding['data'],
    status?: FindingStatus | null,
  ): Promise<Finding | null> {
    const { rows } = await query<FindingRow>(
      `UPDATE finding f SET data = $3, status = COALESCE($4, f.status)
				 FROM scan s, project p
				 WHERE s.id = f.scan_id AND p.id = s.project_id
				   AND p.tenant_id = $1 AND f.id = $2
				 RETURNING f.*`,
      [tenantId, id, data, status ?? null],
    );
    return rows[0] ? toFinding(rows[0]) : null;
  },
};
