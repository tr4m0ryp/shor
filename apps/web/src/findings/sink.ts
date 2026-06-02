/**
 * Findings sink (LAUNCH-SPEC §6, Phase 5, ADR-030/031/047).
 *
 * The connectivity-only sink the worker calls to land its §6.1 findings (and the
 * optional attack-surface document) for a scan. It:
 *   1. validates each candidate against the §6.1 schema,
 *   2. recomputes the stable `fingerprint` + `partialFingerprints` (ADR-031) so
 *      the datastore — not the emitter — owns the canonical diff key,
 *   3. persists via `findingRepo` (idempotent per fingerprint within a scan) and
 *      upserts the attack-surface JSONB via `attackSurfaceRepo`.
 *
 * Exposed two ways: a typed `ingestFindings(...)` for in-process callers and a
 * thin `handleIngestFindings(...)` HTTP handler for `POST /scans/:id/findings`.
 */

import { authenticate } from '../auth/middleware.js';
import { scopedTenantId } from '../auth/tenant-scope.js';
import { attackSurfaceRepo, findingRepo, scanRepo } from '../db/repositories/index.js';
import type { AttackSurfaceData, Finding, FindingRecord, ScanId, TenantId } from '../domain/types.js';
import { withFingerprints } from './fingerprint.js';
import { assertValidFindings } from './validate.js';

/** Response envelope shared with the router (mirrors `ApiResponse`). */
export interface SinkResponse {
  readonly status: number;
  readonly body: Record<string, unknown>;
}

/** Outcome of an ingest: how many findings landed, plus their fingerprints. */
export interface IngestResult {
  readonly scanId: ScanId;
  readonly persisted: number;
  readonly fingerprints: string[];
}

/** Coerce a validated candidate (already §6.1-shaped) into a `FindingRecord`. */
function asFindingRecord(candidate: unknown): FindingRecord {
  return candidate as FindingRecord;
}

/**
 * Persist a batch of findings for a scan. Validates, recomputes fingerprints,
 * and writes each record; existing rows with the same fingerprint within the
 * scan are updated in place so re-ingest is idempotent. Optionally upserts the
 * attack-surface document.
 *
 * The scan must belong to `tenantId` (verified via `scanRepo.findById`) — this
 * is the tenant-scoping choke point for the sink (ADR-044).
 */
export async function ingestFindings(
  tenantId: TenantId,
  scanId: ScanId,
  findings: readonly unknown[],
  attackSurface?: AttackSurfaceData,
): Promise<IngestResult> {
  const scan = await scanRepo.findById(tenantId, scanId);
  if (!scan) {
    throw new SinkScanNotFoundError(scanId);
  }

  assertValidFindings(findings);

  const fingerprints: string[] = [];
  for (const candidate of findings) {
    const record = withFingerprints(asFindingRecord(candidate));
    const persisted = await upsertFinding(tenantId, scanId, record);
    fingerprints.push(persisted.fingerprint);
  }

  if (attackSurface !== undefined) {
    const existing = await attackSurfaceRepo.findByScan(tenantId, scanId);
    if (!existing) {
      await attackSurfaceRepo.create({ scanId, data: attackSurface });
    }
  }

  return { scanId, persisted: fingerprints.length, fingerprints };
}

/** Raised when the target scan does not exist for the caller's tenant. */
export class SinkScanNotFoundError extends Error {
  constructor(public readonly scanId: ScanId) {
    super(`scan not found for tenant: ${scanId}`);
    this.name = 'SinkScanNotFoundError';
  }
}

/**
 * Insert a finding, or refresh the existing row when its fingerprint already
 * exists in the scan (idempotent re-ingest). The `data` JSONB always carries the
 * recomputed fingerprint block so storage stays canonical.
 */
async function upsertFinding(tenantId: TenantId, scanId: ScanId, record: FindingRecord): Promise<Finding> {
  const existing = await findingRepo.findByFingerprint(tenantId, scanId, record.fingerprint);
  if (existing) {
    return existing;
  }
  return findingRepo.create({
    scanId,
    fingerprint: record.fingerprint,
    status: record.status ?? 'new',
    data: record,
  });
}

// ─────────────────────────── HTTP handler ───────────────────────────

function isAttackSurface(value: unknown): value is AttackSurfaceData {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * `POST /scans/:id/findings` — thin HTTP wrapper over `ingestFindings`.
 * Authenticates + tenant-scopes via the session cookie, then lands the batch.
 * Body: `{ findings: FindingRecord[], attackSurface?: AttackSurfaceData }`.
 */
export async function handleIngestFindings(
  scanId: ScanId,
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
): Promise<SinkResponse> {
  const auth = authenticate(cookieHeader);
  if (!auth.ok) {
    return { status: auth.status, body: { error: auth.error } };
  }
  const tenantId = scopedTenantId(auth.principal);

  const findings = body.findings;
  if (!Array.isArray(findings)) {
    return { status: 400, body: { error: 'body.findings must be an array' } };
  }

  const attackSurface = isAttackSurface(body.attackSurface) ? body.attackSurface : undefined;

  try {
    const result = await ingestFindings(tenantId, scanId, findings, attackSurface);
    return { status: 200, body: { ...result } };
  } catch (err) {
    return sinkError(err);
  }
}

/** Map sink/validation errors to HTTP responses (400 client, 404 missing). */
function sinkError(err: unknown): SinkResponse {
  if (err instanceof SinkScanNotFoundError) {
    return { status: 404, body: { error: err.message } };
  }
  if (err instanceof Error && err.name === 'FindingValidationError') {
    const issues = (err as { issues?: unknown }).issues;
    return { status: 400, body: { error: err.message, issues: issues ?? [] } };
  }
  const msg = err instanceof Error ? err.message : String(err);
  return { status: 500, body: { error: msg } };
}
