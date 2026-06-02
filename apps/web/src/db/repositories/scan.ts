/**
 * Scan repository (LAUNCH-SPEC §4.3, ADR-015/019).
 *
 * One scan = one pipeline run against a CodebaseVersion + live URL, backed by a
 * Temporal workflow (`aegis-<scanId>`). Hangs off `project`; queries join
 * through `project` and filter by `tenant_id` for tenant scoping.
 */

import { query } from '../../cloud/pg.js';
import type { NewScan, ProjectId, Scan, ScanId, ScanStatus, TenantId } from '../../domain/types.js';
import { type ScanRow, toScan } from './rows.js';

const SELECT_SCOPED = `
	SELECT s.* FROM scan s
	JOIN project p ON p.id = s.project_id
	WHERE p.tenant_id = $1`;

export const scanRepo = {
  async create(input: NewScan): Promise<Scan> {
    const { rows } = await query<ScanRow>(
      `INSERT INTO scan
			   (project_id, codebase_ver_id, temporal_workflow_id, status, started_at, finished_at)
			 VALUES ($1, $2, $3, COALESCE($4, 'pending'), $5, $6)
			 RETURNING *`,
      [
        input.projectId,
        input.codebaseVersionId,
        input.temporalWorkflowId,
        input.status ?? null,
        input.startedAt ?? null,
        input.finishedAt ?? null,
      ],
    );
    return toScan(rows[0] as ScanRow);
  },

  async findById(tenantId: TenantId, id: ScanId): Promise<Scan | null> {
    const { rows } = await query<ScanRow>(`${SELECT_SCOPED} AND s.id = $2`, [tenantId, id]);
    return rows[0] ? toScan(rows[0]) : null;
  },

  /**
   * Resolve the owning tenant for a scan WITHOUT a caller-supplied tenant id.
   * Used only by service-token callers (the worker findings sink) that prove
   * trust via the shared token, not a session — the tenant is then derived from
   * the scan so all downstream repo calls stay tenant-scoped. Returns null when
   * the scan does not exist.
   */
  async findTenantById(id: ScanId): Promise<TenantId | null> {
    const { rows } = await query<{ tenant_id: string }>(
      `SELECT p.tenant_id FROM scan s JOIN project p ON p.id = s.project_id WHERE s.id = $1`,
      [id],
    );
    return rows[0] ? rows[0].tenant_id : null;
  },

  async listByProject(tenantId: TenantId, projectId: ProjectId): Promise<Scan[]> {
    const { rows } = await query<ScanRow>(
      `${SELECT_SCOPED} AND s.project_id = $2 ORDER BY s.started_at DESC NULLS LAST`,
      [tenantId, projectId],
    );
    return rows.map(toScan);
  },

  /** Set the Temporal workflow id once the workflow has been started. */
  async setWorkflowId(tenantId: TenantId, id: ScanId, workflowId: string): Promise<Scan | null> {
    const { rows } = await query<ScanRow>(
      `UPDATE scan s SET temporal_workflow_id = $3
			 FROM project p
			 WHERE p.id = s.project_id AND p.tenant_id = $1 AND s.id = $2
			 RETURNING s.*`,
      [tenantId, id, workflowId],
    );
    return rows[0] ? toScan(rows[0]) : null;
  },

  /**
   * Transition scan status; stamps started_at/finished_at as the lifecycle
   * dictates (running → started_at; terminal → finished_at).
   */
  async setStatus(tenantId: TenantId, id: ScanId, status: ScanStatus): Promise<Scan | null> {
    const terminal = status === 'completed' || status === 'failed' || status === 'cancelled';
    const { rows } = await query<ScanRow>(
      `UPDATE scan s SET
			   status = $3,
			   started_at = CASE WHEN $3 = 'running' AND s.started_at IS NULL
			                     THEN now() ELSE s.started_at END,
			   finished_at = CASE WHEN $4 THEN now() ELSE s.finished_at END
			 FROM project p
			 WHERE p.id = s.project_id AND p.tenant_id = $1 AND s.id = $2
			 RETURNING s.*`,
      [tenantId, id, status, terminal],
    );
    return rows[0] ? toScan(rows[0]) : null;
  },
};
