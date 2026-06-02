/**
 * Finding repository (LAUNCH-SPEC §4.3 + §6.1, ADR-030/031/032/033).
 *
 * Findings are stored as JSONB (`data`) in storron's shape, keyed by the stable
 * `fingerprint` for scan-to-scan diffs. Hangs off `scan`; queries join through
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

  /** Look up a finding by its stable fingerprint within one scan (diff path). */
  async findByFingerprint(tenantId: TenantId, scanId: ScanId, fingerprint: string): Promise<Finding | null> {
    const { rows } = await query<FindingRow>(`${SELECT_SCOPED} AND f.scan_id = $2 AND f.fingerprint = $3`, [
      tenantId,
      scanId,
      fingerprint,
    ]);
    return rows[0] ? toFinding(rows[0]) : null;
  },

  /** All fingerprints present in a scan (used to compute new/fixed/regressed). */
  async fingerprintsForScan(tenantId: TenantId, scanId: ScanId): Promise<string[]> {
    const { rows } = await query<{ fingerprint: string }>(
      `SELECT f.fingerprint FROM finding f
			 JOIN scan s ON s.id = f.scan_id
			 JOIN project p ON p.id = s.project_id
			 WHERE p.tenant_id = $1 AND f.scan_id = $2`,
      [tenantId, scanId],
    );
    return rows.map((r) => r.fingerprint);
  },

  async updateStatus(tenantId: TenantId, id: FindingId, status: FindingStatus): Promise<Finding | null> {
    const { rows } = await query<FindingRow>(
      `UPDATE finding f SET status = $3
			 FROM scan s, project p
			 WHERE s.id = f.scan_id AND p.id = s.project_id
			   AND p.tenant_id = $1 AND f.id = $2
			 RETURNING f.*`,
      [tenantId, id, status],
    );
    return rows[0] ? toFinding(rows[0]) : null;
  },
};
