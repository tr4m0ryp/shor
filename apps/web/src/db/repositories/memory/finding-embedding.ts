// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * finding_embedding repository — the project-local memory tier (T1/T3).
 *
 * Mirrors finding.ts: parameterized `pg` queries, snake_case-row -> camelCase
 * mappers, tenant scoping. Every method routes through {@link withTenantContext}
 * so the RLS policy (0008_memory.sql) sees the `app.tenant_id`/`app.project_id`
 * claim. Vectors go in as `halfvec` text literals; the large vec columns are
 * NOT returned on the default read shape (retrieval reads them via `nearest`).
 *
 * Out of scope here (per task 001): embedding GENERATION (002) and the full
 * two-tier retrieval/rerank pipeline (012). `nearest` is the minimal ANN seam
 * those tasks build on and that the smoke test exercises.
 */

import type { PoolClient } from 'pg';
import { type Embedding, parseHalfvec, type TenantScope, toHalfvec, withTenantContext } from './context.js';

/** Structured columns for the SQL pre-filter + exact-identifier BM25 (T3). */
export interface FindingEmbeddingInput {
  readonly tenantId: string;
  readonly projectId: string;
  readonly scanId?: string | null;
  readonly vecCode?: Embedding | null;
  readonly vecText?: Embedding | null;
  readonly cwe?: string | null;
  readonly vulnClass?: string | null;
  readonly severity?: string | null;
  readonly route?: string | null;
  readonly source?: string | null;
  readonly sink?: string | null;
  readonly componentVer?: string | null;
  readonly confidence?: string | null;
}

/** Read shape — structured columns only; vectors stay in the DB (they are large). */
export interface FindingEmbedding {
  readonly id: string;
  readonly tenantId: string;
  readonly projectId: string;
  readonly scanId: string | null;
  readonly cwe: string | null;
  readonly vulnClass: string | null;
  readonly severity: string | null;
  readonly route: string | null;
  readonly source: string | null;
  readonly sink: string | null;
  readonly componentVer: string | null;
  readonly confidence: string | null;
  readonly createdAt: string;
}

/** A `nearest` hit — a row plus its cosine distance to the query vector. */
export interface FindingEmbeddingMatch extends FindingEmbedding {
  /** pgvector cosine distance (`<=>`); 0 = identical, 2 = opposite. */
  readonly distance: number;
}

interface Row {
  id: string;
  tenant_id: string;
  project_id: string;
  scan_id: string | null;
  cwe: string | null;
  vuln_class: string | null;
  severity: string | null;
  route: string | null;
  source: string | null;
  sink: string | null;
  component_ver: string | null;
  confidence: string | null;
  created_at: unknown;
}

function toObj(r: Row): FindingEmbedding {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    projectId: r.project_id,
    scanId: r.scan_id,
    cwe: r.cwe,
    vulnClass: r.vuln_class,
    severity: r.severity,
    route: r.route,
    source: r.source,
    sink: r.sink,
    componentVer: r.component_ver,
    confidence: r.confidence,
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : String(r.created_at),
  };
}

const RETURN_COLS = `id, tenant_id, project_id, scan_id, cwe, vuln_class, severity,
  route, source, sink, component_ver, confidence, created_at`;

/** Which dense column a nearest-neighbour query ranks on. */
export type VecColumn = 'vec_code' | 'vec_text';

export const findingEmbeddingRepo = {
  /** Persist one finding's embeddings + structured columns in the local tier. */
  async create(input: FindingEmbeddingInput): Promise<FindingEmbedding> {
    return withTenantContext({ tenantId: input.tenantId, projectId: input.projectId }, async (c: PoolClient) => {
      const { rows } = await c.query<Row>(
        `INSERT INTO finding_embedding
           (tenant_id, project_id, scan_id, vec_code, vec_text, cwe, vuln_class,
            severity, route, source, sink, component_ver, confidence)
         VALUES ($1, $2, $3, $4::halfvec, $5::halfvec, $6, $7, $8, $9, $10, $11, $12, $13)
         RETURNING ${RETURN_COLS}`,
        [
          input.tenantId,
          input.projectId,
          input.scanId ?? null,
          toHalfvec(input.vecCode),
          toHalfvec(input.vecText),
          input.cwe ?? null,
          input.vulnClass ?? null,
          input.severity ?? null,
          input.route ?? null,
          input.source ?? null,
          input.sink ?? null,
          input.componentVer ?? null,
          input.confidence ?? null,
        ],
      );
      return toObj(rows[0] as Row);
    });
  },

  /** List a project's embeddings (structured columns only), newest first. */
  async listByProject(scope: Required<TenantScope>, limit = 100): Promise<FindingEmbedding[]> {
    return withTenantContext(scope, async (c) => {
      const { rows } = await c.query<Row>(
        `SELECT ${RETURN_COLS} FROM finding_embedding
         WHERE project_id = $1 ORDER BY created_at DESC LIMIT $2`,
        [scope.projectId, limit],
      );
      return rows.map(toObj);
    });
  },

  /**
   * Approximate-nearest-neighbour over one dense column (the retrieval seam for
   * task 012). Ranks by cosine distance; optional CWE pre-filter uses the
   * `(tenant_id, project_id, cwe)` B-tree. RLS confines the scan to the scoped
   * tenant/project. Rows with a NULL vector are skipped.
   */
  async nearest(
    scope: TenantScope,
    query: Embedding,
    opts: { column?: VecColumn; limit?: number; cwe?: string | null } = {},
  ): Promise<FindingEmbeddingMatch[]> {
    const column: VecColumn = opts.column ?? 'vec_text';
    const literal = toHalfvec(query);
    return withTenantContext(scope, async (c) => {
      const { rows } = await c.query<Row & { distance: number }>(
        `SELECT ${RETURN_COLS}, (${column} <=> $1::halfvec) AS distance
         FROM finding_embedding
         WHERE ${column} IS NOT NULL AND ($2::text IS NULL OR cwe = $2)
         ORDER BY ${column} <=> $1::halfvec
         LIMIT $3`,
        [literal, opts.cwe ?? null, opts.limit ?? 8],
      );
      return rows.map((r) => ({ ...toObj(r), distance: Number(r.distance) }));
    });
  },
};

// Re-export the vector codec so 002/012 share one serialization path.
export { parseHalfvec, toHalfvec };
