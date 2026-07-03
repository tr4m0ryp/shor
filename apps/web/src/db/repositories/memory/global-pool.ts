// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * global_pool repository — the cross-tenant "mega-brain" tier (T2, user chose
 * raw pooling). Reads are cross-tenant by design (RLS `USING (true)` in
 * 0008_memory.sql), so these methods use the plain pool query — NOT the tenant
 * context. `kind` separates a promoted abstraction, a redacted exemplar, and a
 * raw pooled finding.
 *
 * WRITE GUARD (do not remove): cross-tenant writes here are flag-gated at the
 * APP layer (`pooling_enabled`, task 014) behind the T2 guardrails — mandatory
 * secret/PII scrub, a DPA/consent legal basis, and a standing
 * red-team-extraction audit. This repository is the storage seam ONLY; it does
 * NOT itself decide whether pooling is permitted. Callers (task 014) MUST gate
 * `insert` on that flag AND scrub secrets before persisting.
 */

import { query } from '../../../cloud/pg.js';
import { type Embedding, parseHalfvec, toHalfvec } from './context.js';

/** A pooled item's role in the shared corpus. */
export type GlobalPoolKind = 'abstraction' | 'exemplar' | 'finding';

export interface GlobalPoolInput {
  readonly kind: GlobalPoolKind;
  readonly payload: Record<string, unknown>;
  readonly vecCode?: Embedding | null;
  readonly vecText?: Embedding | null;
  /** k-anonymity aggregate count; defaults to 1. */
  readonly kAnonCount?: number;
  /** Provenance only; may be null once aggregated. */
  readonly sourceTenant?: string | null;
}

export interface GlobalPoolItem {
  readonly id: string;
  readonly kind: GlobalPoolKind;
  readonly payload: Record<string, unknown>;
  readonly kAnonCount: number;
  readonly sourceTenant: string | null;
  readonly createdAt: string;
}

export interface GlobalPoolMatch extends GlobalPoolItem {
  readonly distance: number;
}

interface Row {
  id: string;
  kind: string;
  payload: Record<string, unknown>;
  k_anon_count: number;
  source_tenant: string | null;
  created_at: unknown;
}

function toObj(r: Row): GlobalPoolItem {
  return {
    id: r.id,
    kind: r.kind as GlobalPoolKind,
    payload: r.payload,
    kAnonCount: Number(r.k_anon_count),
    sourceTenant: r.source_tenant,
    createdAt: r.created_at instanceof Date ? r.created_at.toISOString() : String(r.created_at),
  };
}

const RETURN_COLS = 'id, kind, payload, k_anon_count, source_tenant, created_at';

export const globalPoolRepo = {
  /**
   * Persist a pooled item. NOTE: task 014 owns the `pooling_enabled` flag +
   * secret-scrub precondition; calling this without that gate would pool raw
   * cross-tenant data, which the T2 guardrails forbid until the flag is on.
   */
  async insert(input: GlobalPoolInput): Promise<GlobalPoolItem> {
    const { rows } = await query<Row>(
      `INSERT INTO global_pool (kind, vec_code, vec_text, payload, k_anon_count, source_tenant)
       VALUES ($1, $2::halfvec, $3::halfvec, $4, COALESCE($5, 1), $6)
       RETURNING ${RETURN_COLS}`,
      [
        input.kind,
        toHalfvec(input.vecCode),
        toHalfvec(input.vecText),
        input.payload,
        input.kAnonCount ?? null,
        input.sourceTenant ?? null,
      ],
    );
    return toObj(rows[0] as Row);
  },

  async findById(id: string): Promise<GlobalPoolItem | null> {
    const { rows } = await query<Row>(`SELECT ${RETURN_COLS} FROM global_pool WHERE id = $1`, [id]);
    const row = rows[0];
    return row ? toObj(row) : null;
  },

  /** Increment an item's k-anonymity aggregate count (a new tenant matched it). */
  async bumpKAnon(id: string, by = 1): Promise<GlobalPoolItem | null> {
    const { rows } = await query<Row>(
      `UPDATE global_pool SET k_anon_count = k_anon_count + $2 WHERE id = $1 RETURNING ${RETURN_COLS}`,
      [id, by],
    );
    const row = rows[0];
    return row ? toObj(row) : null;
  },

  /**
   * Cross-tenant approximate-nearest-neighbour (the global half of the two-tier
   * retrieval fused in task 012). Ranks by cosine distance on the chosen dense
   * column; optional `kind` pre-filter uses the `kind` B-tree.
   */
  async nearest(
    queryVec: Embedding,
    opts: { column?: 'vec_code' | 'vec_text'; limit?: number; kind?: GlobalPoolKind | null } = {},
  ): Promise<GlobalPoolMatch[]> {
    const column = opts.column ?? 'vec_text';
    const literal = toHalfvec(queryVec);
    const { rows } = await query<Row & { distance: number }>(
      `SELECT ${RETURN_COLS}, (${column} <=> $1::halfvec) AS distance
       FROM global_pool
       WHERE ${column} IS NOT NULL AND ($2::text IS NULL OR kind = $2)
       ORDER BY ${column} <=> $1::halfvec
       LIMIT $3`,
      [literal, opts.kind ?? null, opts.limit ?? 8],
    );
    return rows.map((r) => ({ ...toObj(r), distance: Number(r.distance) }));
  },
};

export { parseHalfvec };
