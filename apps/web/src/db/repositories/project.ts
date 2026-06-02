/**
 * Project repository (LAUNCH-SPEC §4.3, ADR-015).
 *
 * A project = a named target (live site + connected repo + optional schedule).
 * Tenant-scoped on every query.
 */

import { query } from '../../cloud/pg.js';
import type { NewProject, Project, ProjectId, TenantId } from '../../domain/types.js';
import { type ProjectRow, toProject } from './rows.js';

export const projectRepo = {
  async create(input: NewProject): Promise<Project> {
    const { rows } = await query<ProjectRow>(
      `INSERT INTO project
			   (tenant_id, name, target_url, repo_installation_id, schedule, auth_config)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 RETURNING *`,
      [input.tenantId, input.name, input.targetUrl, input.repoInstallationId, input.schedule, input.authConfig],
    );
    return toProject(rows[0] as ProjectRow);
  },

  async findById(tenantId: TenantId, id: ProjectId): Promise<Project | null> {
    const { rows } = await query<ProjectRow>('SELECT * FROM project WHERE tenant_id = $1 AND id = $2', [tenantId, id]);
    return rows[0] ? toProject(rows[0]) : null;
  },

  async listByTenant(tenantId: TenantId): Promise<Project[]> {
    const { rows } = await query<ProjectRow>('SELECT * FROM project WHERE tenant_id = $1 ORDER BY created_at DESC', [
      tenantId,
    ]);
    return rows.map(toProject);
  },

  /** Patch mutable project fields; tenant-scoped. Returns the updated row. */
  async update(
    tenantId: TenantId,
    id: ProjectId,
    patch: Partial<Pick<Project, 'name' | 'targetUrl' | 'repoInstallationId' | 'schedule' | 'authConfig'>>,
  ): Promise<Project | null> {
    const { rows } = await query<ProjectRow>(
      `UPDATE project SET
			   name = COALESCE($3, name),
			   target_url = COALESCE($4, target_url),
			   repo_installation_id = COALESCE($5, repo_installation_id),
			   schedule = COALESCE($6, schedule),
			   auth_config = COALESCE($7, auth_config)
			 WHERE tenant_id = $1 AND id = $2
			 RETURNING *`,
      [
        tenantId,
        id,
        patch.name ?? null,
        patch.targetUrl ?? null,
        patch.repoInstallationId ?? null,
        patch.schedule ?? null,
        patch.authConfig ?? null,
      ],
    );
    return rows[0] ? toProject(rows[0]) : null;
  },

  async delete(tenantId: TenantId, id: ProjectId): Promise<void> {
    await query('DELETE FROM project WHERE tenant_id = $1 AND id = $2', [tenantId, id]);
  },
};
