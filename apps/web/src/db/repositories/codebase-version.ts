/**
 * CodebaseVersion repository (LAUNCH-SPEC §4.3, ADR-015).
 *
 * Immutable snapshots minted per ingest. Hangs off `project`; queries join
 * through `project` and filter by `tenant_id` so reads are tenant-scoped even
 * though the row only carries `project_id` (defense-in-depth row scoping).
 */

import { query } from '../../cloud/pg.js';
import type {
  CodebaseVersion,
  CodebaseVersionId,
  NewCodebaseVersion,
  ProjectId,
  TenantId,
} from '../../domain/types.js';
import { type CodebaseVersionRow, toCodebaseVersion } from './rows.js';

const SELECT_SCOPED = `
	SELECT cv.* FROM codebase_ver cv
	JOIN project p ON p.id = cv.project_id
	WHERE p.tenant_id = $1`;

export const codebaseVersionRepo = {
  async create(input: NewCodebaseVersion): Promise<CodebaseVersion> {
    const { rows } = await query<CodebaseVersionRow>(
      `INSERT INTO codebase_ver (project_id, source_kind, git_sha, gcs_prefix)
			 VALUES ($1, $2, $3, $4)
			 RETURNING *`,
      [input.projectId, input.sourceKind, input.gitSha, input.gcsPrefix],
    );
    return toCodebaseVersion(rows[0] as CodebaseVersionRow);
  },

  async findById(tenantId: TenantId, id: CodebaseVersionId): Promise<CodebaseVersion | null> {
    const { rows } = await query<CodebaseVersionRow>(`${SELECT_SCOPED} AND cv.id = $2`, [tenantId, id]);
    return rows[0] ? toCodebaseVersion(rows[0]) : null;
  },

  async listByProject(tenantId: TenantId, projectId: ProjectId): Promise<CodebaseVersion[]> {
    const { rows } = await query<CodebaseVersionRow>(
      `${SELECT_SCOPED} AND cv.project_id = $2 ORDER BY cv.created_at DESC`,
      [tenantId, projectId],
    );
    return rows.map(toCodebaseVersion);
  },

  /** Most recent version for a project (the default ingest to scan). */
  async latestForProject(tenantId: TenantId, projectId: ProjectId): Promise<CodebaseVersion | null> {
    const { rows } = await query<CodebaseVersionRow>(
      `${SELECT_SCOPED} AND cv.project_id = $2
			 ORDER BY cv.created_at DESC LIMIT 1`,
      [tenantId, projectId],
    );
    return rows[0] ? toCodebaseVersion(rows[0]) : null;
  },
};
