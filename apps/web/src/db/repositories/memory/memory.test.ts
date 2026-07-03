// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Learning-memory repository tests (task 001).
 *
 * Two layers: (1) always-on pure-logic tests for the `halfvec` codec; (2) a
 * DB-gated smoke test that inserts + queries a real vector row end-to-end. The
 * smoke test needs a Postgres with pgvector + 0008_memory.sql applied and the
 * `CLOUD_SQL_*` env pointing at it; opt in with `MEMORY_SMOKE_DB=1`. It is
 * skipped by default so `pnpm vitest` passes with no database.
 */

import { afterAll, describe, expect, it } from 'vitest';
import { closePool, query } from '../../../cloud/pg.js';
import { EMBEDDING_DIM, parseHalfvec, toHalfvec } from './context.js';
import { findingEmbeddingRepo } from './finding-embedding.js';

/** A deterministic unit vector of the pinned dimensionality. */
function vec(seed: number): number[] {
  return Array.from({ length: EMBEDDING_DIM }, (_, i) => Math.sin(seed + i) / 10);
}

describe('halfvec codec', () => {
  it('round-trips a 1024-dim vector through the text literal', () => {
    const v = vec(1);
    const literal = toHalfvec(v);
    expect(literal?.startsWith('[')).toBe(true);
    expect(literal?.endsWith(']')).toBe(true);
    const parsed = parseHalfvec(literal);
    expect(parsed).toHaveLength(EMBEDDING_DIM);
    expect(parsed?.[0]).toBeCloseTo(v[0] as number, 10);
  });

  it('serializes null/undefined to a NULL column value', () => {
    expect(toHalfvec(null)).toBeNull();
    expect(toHalfvec(undefined)).toBeNull();
  });

  it('rejects a wrong-dimension vector', () => {
    expect(() => toHalfvec([1, 2, 3])).toThrow(/1024-dim/);
  });

  it('rejects a non-finite value', () => {
    const bad = vec(2);
    bad[5] = Number.NaN;
    expect(() => toHalfvec(bad)).toThrow(/non-finite/);
  });

  it('parses null and malformed literals to null', () => {
    expect(parseHalfvec(null)).toBeNull();
    expect(parseHalfvec('not-a-vector')).toBeNull();
    expect(parseHalfvec('[]')).toEqual([]);
  });
});

// ─── DB-gated end-to-end smoke: insert a vector row, retrieve it by ANN ──────
const hasDb = process.env.MEMORY_SMOKE_DB === '1';

describe.runIf(hasDb)('finding_embedding smoke (live pgvector)', () => {
  let tenantId = '';
  let projectId = '';

  afterAll(async () => {
    if (tenantId) await query('DELETE FROM tenant WHERE id = $1', [tenantId]);
    await closePool();
  });

  it('inserts an embedding and finds it by nearest-neighbour', async () => {
    const t = await query<{ id: string }>(`INSERT INTO tenant (org_name, idp_tenant_id) VALUES ($1, $2) RETURNING id`, [
      'memtest',
      `memtest-${Date.now()}`,
    ]);
    tenantId = (t.rows[0] as { id: string }).id;
    const p = await query<{ id: string }>(
      `INSERT INTO project (tenant_id, name, target_url) VALUES ($1, $2, $3) RETURNING id`,
      [tenantId, 'memtest', 'https://example.test'],
    );
    projectId = (p.rows[0] as { id: string }).id;

    const created = await findingEmbeddingRepo.create({
      tenantId,
      projectId,
      vecText: vec(1),
      cwe: 'CWE-89',
      severity: 'high',
    });
    expect(created.cwe).toBe('CWE-89');

    const hits = await findingEmbeddingRepo.nearest({ tenantId, projectId }, vec(1), {
      column: 'vec_text',
      limit: 5,
    });
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0]?.id).toBe(created.id);
    expect(hits[0]?.distance).toBeLessThan(0.01);
  });
});
