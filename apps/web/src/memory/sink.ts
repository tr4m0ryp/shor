// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Memory store sink — the thin DB seam the worker's two-tier RAG reaches over
 * HTTP (`POST /scans/:id/memory/nearest` + `/memory/embeddings`).
 *
 * The worker owns all memory reasoning (embed, fuse, rerank, scrub); this route
 * only runs the pgvector `nearest` reads and the `finding_embedding`/`fp_memory`
 * inserts, since apps/web is the sole holder of DB access. Auth + tenant scoping
 * reuse the findings-sink trust model EXACTLY: a `Bearer <sinkToken>` authorizes
 * the call and the tenant/project are DERIVED FROM THE SCAN server-side — the
 * worker-supplied scope is never trusted, so RLS isolation holds.
 */

import { scanRepo } from '../db/repositories/index.js';
import {
  type Embedding,
  findingEmbeddingRepo,
  fpMemoryRepo,
  globalPoolRepo,
  type GlobalPoolKind,
  type VecColumn,
} from '../db/repositories/memory/index.js';
import type { ScanId } from '../domain/types.js';
import { resolveSinkTenant, type SinkResponse } from '../findings/sink.js';

/** Bound the neighbours a single recall may pull (mirrors the worker recall depth). */
const MAX_LIMIT = 50;

function asVector(value: unknown): Embedding | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  return value.every((n) => typeof n === 'number' && Number.isFinite(n))
    ? (value as number[])
    : null;
}

function asColumn(value: unknown): VecColumn {
  return value === 'vec_code' ? 'vec_code' : 'vec_text';
}

function asLimit(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return 8;
  return Math.min(Math.floor(n), MAX_LIMIT);
}

function asStr(value: unknown): string | null {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : null;
}

function asKind(value: unknown): GlobalPoolKind | null {
  return value === 'abstraction' || value === 'exemplar' || value === 'finding' ? value : null;
}

/** Resolve `{tenantId, projectId}` for a scan, or an error response. */
async function resolveScope(
  scanId: ScanId,
  cookieHeader: string | undefined,
  authHeader: string | undefined,
): Promise<{ ok: true; tenantId: string; projectId: string } | { ok: false; res: SinkResponse }> {
  const resolved = await resolveSinkTenant(scanId, cookieHeader, authHeader);
  if (!resolved.ok) return { ok: false, res: { status: resolved.status, body: { error: resolved.error } } };
  const scan = await scanRepo.findById(resolved.tenantId, scanId);
  if (!scan) return { ok: false, res: { status: 404, body: { error: `scan not found: ${scanId}` } } };
  return { ok: true, tenantId: resolved.tenantId, projectId: scan.projectId };
}

/** `POST /scans/:id/memory/nearest` — two-tier ANN read for RAG recall. */
async function handleNearest(
  scanId: ScanId,
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
  authHeader: string | undefined,
): Promise<SinkResponse> {
  const scope = await resolveScope(scanId, cookieHeader, authHeader);
  if (!scope.ok) return scope.res;

  const vector = asVector(body.vector);
  if (!vector) return { status: 400, body: { error: 'body.vector must be a non-empty number[]' } };
  const column = asColumn(body.column);
  const limit = asLimit(body.limit);

  if (body.tier === 'global') {
    const matches = await globalPoolRepo.nearest(vector, { column, limit, kind: asKind(body.kind) });
    return {
      status: 200,
      body: {
        matches: matches.map((m) => ({ id: m.id, distance: m.distance, kind: m.kind, payload: m.payload })),
      },
    };
  }

  // Local tier (default): project-scoped, RLS-isolated to the scan's tenant.
  const matches = await findingEmbeddingRepo.nearest(
    { tenantId: scope.tenantId, projectId: scope.projectId },
    vector,
    { column, limit, cwe: asStr(body.cwe) },
  );
  return {
    status: 200,
    body: {
      matches: matches.map((m) => ({
        id: m.id,
        distance: m.distance,
        cwe: m.cwe,
        vulnClass: m.vulnClass,
        severity: m.severity,
        route: m.route,
        source: m.source,
        sink: m.sink,
        componentVer: m.componentVer,
        confidence: m.confidence,
      })),
    },
  };
}

/** `POST /scans/:id/memory/embeddings` — persist one finding_embedding or fp_memory row. */
async function handleEmbeddings(
  scanId: ScanId,
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
  authHeader: string | undefined,
): Promise<SinkResponse> {
  const scope = await resolveScope(scanId, cookieHeader, authHeader);
  if (!scope.ok) return scope.res;
  const { tenantId, projectId } = scope;

  if (body.kind === 'fp') {
    const fingerprint = asStr(body.fingerprint);
    if (!fingerprint) return { status: 400, body: { error: 'fp write requires a fingerprint' } };
    const row = await fpMemoryRepo.upsert({
      tenantId,
      projectId,
      fingerprint,
      reason: asStr(body.reason),
      vecText: asVector(body.vecText),
      decision: asStr(body.decision),
    });
    return { status: 200, body: { id: row.id } };
  }

  // Default: a finding_embedding local-tier row.
  const row = await findingEmbeddingRepo.create({
    tenantId,
    projectId,
    scanId,
    vecCode: asVector(body.vecCode),
    vecText: asVector(body.vecText),
    cwe: asStr(body.cwe),
    vulnClass: asStr(body.vulnClass),
    severity: asStr(body.severity),
    route: asStr(body.route),
    source: asStr(body.source),
    sink: asStr(body.sink),
    componentVer: asStr(body.componentVer),
    confidence: asStr(body.confidence),
  });
  return { status: 200, body: { id: row.id } };
}

/**
 * Route a `POST /scans/:id/memory/:op` request. `op` is `nearest` (RAG recall)
 * or `embeddings` (learning-memory write). Errors map to 500 so the worker's
 * fail-open wrappers degrade gracefully (prompt unchanged / write skipped).
 */
export async function handleMemoryRequest(
  scanId: ScanId,
  op: string,
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
  authHeader?: string | undefined,
): Promise<SinkResponse> {
  try {
    if (op === 'nearest') return await handleNearest(scanId, body, cookieHeader, authHeader);
    if (op === 'embeddings') return await handleEmbeddings(scanId, body, cookieHeader, authHeader);
    return { status: 404, body: { error: `unknown memory op: ${op}` } };
  } catch (err) {
    return { status: 500, body: { error: err instanceof Error ? err.message : String(err) } };
  }
}
