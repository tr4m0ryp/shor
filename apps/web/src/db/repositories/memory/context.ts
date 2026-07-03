// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Shared helpers for the learning-memory repositories (engine-proof-and-memory
 * T1/T3). Two concerns: (1) `halfvec` (fp16, 1024-dim) serialization to/from the
 * Postgres text literal pgvector expects; (2) the RLS session-claim seam.
 *
 * RLS seam (documented, flagged): 0008_memory.sql gates the tenant-scoped tables
 * (`finding_embedding`, `fp_memory`) on `app.tenant_id` / `app.project_id`
 * settings. There is NO Supabase-SDK / JWT-claim wiring in this codebase's `pg`
 * connection model (config.ts), so tenant scoping is enforced here with
 * `set_config(..., is_local => true)` inside a transaction — the vanilla-`pg`
 * equivalent of `SET LOCAL`. Callers MUST route every tenant-scoped read/write
 * through {@link withTenantContext} so the policy sees the claim.
 *
 * CAVEAT (flagged per task stop-condition): RLS + FORCE binds the table owner,
 * but a BYPASSRLS/superuser role (e.g. Supabase's `postgres`) bypasses RLS
 * regardless. For isolation to actually enforce, the app must connect as a
 * non-BYPASSRLS role. This does not change the repo API; it is a deployment note.
 */

import type { PoolClient } from 'pg';
import { withTransaction } from '../../../cloud/pg.js';

/** Embedding dimensionality pinned across the memory store (T1/F13). */
export const EMBEDDING_DIM = 1024;

/** A dense embedding vector — exactly {@link EMBEDDING_DIM} finite numbers. */
export type Embedding = readonly number[];

/**
 * Serialize an embedding to the `halfvec` text literal pgvector parses
 * (`[a,b,c]`). Returns null for a null/absent vector so a column stays NULL.
 * Throws on a wrong-dimension or non-finite vector — a silent bad write would
 * poison retrieval far downstream.
 */
export function toHalfvec(vec: Embedding | null | undefined): string | null {
  if (vec === null || vec === undefined) return null;
  if (vec.length !== EMBEDDING_DIM) {
    throw new RangeError(`embedding must be ${EMBEDDING_DIM}-dim, got ${vec.length}`);
  }
  for (const n of vec) {
    if (!Number.isFinite(n)) throw new RangeError('embedding contains a non-finite value');
  }
  return `[${vec.join(',')}]`;
}

/** Parse a `halfvec`/`vector` text literal (`[a,b,c]`) back to numbers, or null. */
export function parseHalfvec(raw: unknown): number[] | null {
  if (raw === null || raw === undefined) return null;
  const s = String(raw).trim();
  if (s.length < 2 || s[0] !== '[' || s[s.length - 1] !== ']') return null;
  const inner = s.slice(1, -1).trim();
  if (inner === '') return [];
  return inner.split(',').map((t) => Number(t));
}

/** The session claims that drive RLS on the tenant-scoped memory tables. */
export interface TenantScope {
  readonly tenantId: string;
  /** Optional project narrowing; omit for a tenant-wide read. */
  readonly projectId?: string | null;
}

/**
 * Run `fn` inside a transaction with `app.tenant_id` (+ optional
 * `app.project_id`) set LOCAL so the RLS policies in 0008_memory.sql admit the
 * row. The claim is transaction-scoped (`is_local => true`) — it never leaks to
 * the next pool checkout. `fn` MUST issue its queries on the provided client so
 * they share the session that carries the claim.
 */
export async function withTenantContext<T>(scope: TenantScope, fn: (client: PoolClient) => Promise<T>): Promise<T> {
  return withTransaction(async (client) => {
    await client.query('SELECT set_config($1, $2, true), set_config($3, $4, true)', [
      'app.tenant_id',
      scope.tenantId,
      'app.project_id',
      scope.projectId ?? '',
    ]);
    return fn(client);
  });
}
