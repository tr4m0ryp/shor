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
import { getConfig } from '../config.js';
import { attackSurfaceRepo, findingRepo, scanRepo } from '../db/repositories/index.js';
import type {
  AttackSurfaceData,
  Finding,
  FindingRecord,
  ScanId,
  ScanStatus,
  TenantId,
} from '../domain/types.js';
import { mirrorFindings, mirrorScan } from '../sinas/mirror.js';
import { withFingerprints } from './fingerprint.js';
import { validateFinding } from './validate.js';

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
  /** Count of malformed findings skipped (only present when > 0). */
  readonly skipped?: number;
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

  // Resilient ingest: keep the structurally-valid findings, skip (don't reject
  // the whole batch over) malformed ones. A single bad record must never discard
  // a run's other findings — partial results beat none.
  const valid: unknown[] = [];
  let skipped = 0;
  findings.forEach((candidate, index) => {
    if (validateFinding(candidate, index).length === 0) valid.push(candidate);
    else skipped += 1;
  });

  const fingerprints: string[] = [];
  const records: FindingRecord[] = [];
  for (const candidate of valid) {
    const record = withFingerprints(asFindingRecord(candidate));
    const persisted = await upsertFinding(tenantId, scanId, record);
    fingerprints.push(persisted.fingerprint);
    records.push(record);
  }

  if (attackSurface !== undefined) {
    // Upsert (not create-if-absent): the worker posts the attack surface on every
    // emission — the engine's local synthesis during the run, then the richer
    // Sinas/Opus rewrite on the final `completed` post. Create-if-absent pinned
    // the engine doc (whose schema the dashboard does not render) and dropped the
    // Opus one; last-write-wins lets the final post replace it.
    await attackSurfaceRepo.upsert({ scanId, data: attackSurface });
  }

  // Best-effort hub->Sinas mirror of the fingerprinted findings (keyed by the
  // canonical fingerprint, overlapping the worker's finalize push idempotently);
  // self-swallowing, never affects this ingest's result.
  await mirrorFindings(scanId, records);

  return { scanId, persisted: fingerprints.length, fingerprints, ...(skipped > 0 && { skipped }) };
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
    // Refresh the row in place — the worker re-posts the same fingerprint as the
    // run progresses, upgrading a finding from its initial `firm`/`queued` state to
    // the final live `confirmed`/`exploited` disposition (and improved prose). The
    // previous return-existing-unchanged froze every finding at its first post.
    const updated = await findingRepo.updateData(tenantId, existing.id, record);
    return updated ?? existing;
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

/** Sink statuses the worker may report on its callback; others are ignored. */
const SINK_STATUSES: ReadonlySet<ScanStatus> = new Set<ScanStatus>(['completed', 'failed']);

function asSinkStatus(value: unknown): ScanStatus | undefined {
  return typeof value === 'string' && SINK_STATUSES.has(value as ScanStatus)
    ? (value as ScanStatus)
    : undefined;
}

/** Parse a `Bearer <token>` Authorization header; returns the token or undefined. */
function bearerToken(authHeader: string | undefined): string | undefined {
  if (!authHeader) return undefined;
  const m = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
  return m ? m[1] : undefined;
}

/**
 * Length-independent, timing-safe-ish string equality. Never short-circuits on
 * the first differing byte and never logs either operand — used to compare the
 * presented service token against the configured `sinkToken`.
 */
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Resolve the calling tenant for a findings ingest. Two trust paths:
 *   - SERVICE: a `Bearer <token>` matching `getConfig().sinkToken` authorizes the
 *     call with no session; the tenant is derived from the scan itself (the
 *     worker only knows the scan id). The token is never logged.
 *   - SESSION: the existing UI path — verify the session cookie and tenant-scope.
 */
export async function resolveSinkTenant(
  scanId: ScanId,
  cookieHeader: string | undefined,
  authHeader: string | undefined,
): Promise<{ ok: true; tenantId: TenantId } | { ok: false; status: number; error: string }> {
  const { sinkToken } = getConfig();
  const presented = bearerToken(authHeader);
  if (presented !== undefined && sinkToken !== '' && safeEqual(presented, sinkToken)) {
    const tenantId = await scanRepo.findTenantById(scanId);
    if (!tenantId) return { ok: false, status: 404, error: `scan not found: ${scanId}` };
    return { ok: true, tenantId };
  }

  const auth = authenticate(cookieHeader);
  if (!auth.ok) return { ok: false, status: auth.status, error: auth.error };
  return { ok: true, tenantId: scopedTenantId(auth.principal) };
}

/**
 * `POST /scans/:id/findings` — thin HTTP wrapper over `ingestFindings`.
 *
 * Authorizes via EITHER the worker service token (`Authorization: Bearer
 * <sinkToken>`, tenant resolved from the scan) OR the UI session cookie, then
 * lands the batch. When a service caller supplies a terminal `status`
 * (`completed`/`failed`) the scan is transitioned accordingly. Body:
 * `{ findings: FindingRecord[], attackSurface?: object, status?: "completed"|"failed" }`.
 */
export async function handleIngestFindings(
  scanId: ScanId,
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
  authHeader?: string | undefined,
): Promise<SinkResponse> {
  const resolved = await resolveSinkTenant(scanId, cookieHeader, authHeader);
  if (!resolved.ok) {
    return { status: resolved.status, body: { error: resolved.error } };
  }
  const { tenantId } = resolved;

  const findings = body.findings;
  if (!Array.isArray(findings)) {
    return { status: 400, body: { error: 'body.findings must be an array' } };
  }

  const attackSurface = isAttackSurface(body.attackSurface) ? body.attackSurface : undefined;

  try {
    const result = await ingestFindings(tenantId, scanId, findings, attackSurface);
    const status = asSinkStatus(body.status);
    if (status) {
      const updated = await scanRepo.setStatus(tenantId, scanId, status);
      // Best-effort hub->Sinas mirror of the terminal scan state; self-swallowing.
      if (updated) await mirrorScan(updated);
    }
    return { status: 200, body: { ...result, ...(status ? { scanStatus: status } : {}) } };
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
