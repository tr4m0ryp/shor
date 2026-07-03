// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * fp_memory repository — refuted / demoted findings for next-scan auto-filter.
 *
 * Keyed by the stable finding `fingerprint` per project (upsert-by-fingerprint,
 * mirroring finding.ts re-ingest). The validator DEMOTES a future rediscovery,
 * never hard-deletes it (valid-vuln-yield focus) — `decision` records how it was
 * refuted, and `nearest` gives the fuzzy semantic lookup for near-miss variants.
 * Tenant-scoped via {@link withTenantContext} (RLS in 0008_memory.sql).
 */

import { type Embedding, type TenantScope, toHalfvec, withTenantContext } from './context.js';

/** A refuted/demoted finding to remember. */
export interface FpMemoryInput {
  readonly tenantId: string;
  readonly projectId: string;
  readonly fingerprint: string;
  readonly reason?: string | null;
  readonly vecText?: Embedding | null;
  /** How it was refuted: refuted | demoted | false_positive (free-form). */
  readonly decision?: string | null;
}

export interface FpMemory {
  readonly id: string;
  readonly tenantId: string;
  readonly projectId: string;
  readonly fingerprint: string;
  readonly reason: string | null;
  readonly decision: string;
  readonly decidedAt: string;
}

export interface FpMemoryMatch extends FpMemory {
  readonly distance: number;
}

interface Row {
  id: string;
  tenant_id: string;
  project_id: string;
  fingerprint: string;
  reason: string | null;
  decision: string;
  decided_at: unknown;
}

function toObj(r: Row): FpMemory {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    projectId: r.project_id,
    fingerprint: r.fingerprint,
    reason: r.reason,
    decision: r.decision,
    decidedAt: r.decided_at instanceof Date ? r.decided_at.toISOString() : String(r.decided_at),
  };
}

const RETURN_COLS = 'id, tenant_id, project_id, fingerprint, reason, decision, decided_at';

export const fpMemoryRepo = {
  /**
   * Insert or refresh a refuted finding by (tenant, project, fingerprint). A
   * re-refutation updates the reason/decision/vector and bumps `decided_at`.
   */
  async upsert(input: FpMemoryInput): Promise<FpMemory> {
    return withTenantContext({ tenantId: input.tenantId, projectId: input.projectId }, async (c) => {
      const { rows } = await c.query<Row>(
        `INSERT INTO fp_memory (tenant_id, project_id, fingerprint, reason, vec_text, decision)
         VALUES ($1, $2, $3, $4, $5::halfvec, COALESCE($6, 'refuted'))
         ON CONFLICT (tenant_id, project_id, fingerprint) DO UPDATE SET
           reason = EXCLUDED.reason,
           vec_text = EXCLUDED.vec_text,
           decision = EXCLUDED.decision,
           decided_at = now()
         RETURNING ${RETURN_COLS}`,
        [
          input.tenantId,
          input.projectId,
          input.fingerprint,
          input.reason ?? null,
          toHalfvec(input.vecText),
          input.decision ?? null,
        ],
      );
      return toObj(rows[0] as Row);
    });
  },

  /** Exact fingerprint lookup — the deterministic fast-path auto-filter key. */
  async findByFingerprint(scope: Required<TenantScope>, fingerprint: string): Promise<FpMemory | null> {
    return withTenantContext(scope, async (c) => {
      const { rows } = await c.query<Row>(
        `SELECT ${RETURN_COLS} FROM fp_memory
         WHERE project_id = $1 AND fingerprint = $2`,
        [scope.projectId, fingerprint],
      );
      const row = rows[0];
      return row ? toObj(row) : null;
    });
  },

  /** List a project's remembered false-positives, most-recently-decided first. */
  async listByProject(scope: Required<TenantScope>, limit = 200): Promise<FpMemory[]> {
    return withTenantContext(scope, async (c) => {
      const { rows } = await c.query<Row>(
        `SELECT ${RETURN_COLS} FROM fp_memory
         WHERE project_id = $1 ORDER BY decided_at DESC LIMIT $2`,
        [scope.projectId, limit],
      );
      return rows.map(toObj);
    });
  },

  /** Fuzzy semantic lookup for near-miss variants of a known false-positive. */
  async nearest(scope: TenantScope, query: Embedding, limit = 8): Promise<FpMemoryMatch[]> {
    const literal = toHalfvec(query);
    return withTenantContext(scope, async (c) => {
      const { rows } = await c.query<Row & { distance: number }>(
        `SELECT ${RETURN_COLS}, (vec_text <=> $1::halfvec) AS distance
         FROM fp_memory
         WHERE vec_text IS NOT NULL
         ORDER BY vec_text <=> $1::halfvec
         LIMIT $2`,
        [literal, limit],
      );
      return rows.map((r) => ({ ...toObj(r), distance: Number(r.distance) }));
    });
  },
};
