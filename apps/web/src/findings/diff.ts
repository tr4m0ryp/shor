/**
 * Scan-to-scan status transitions (LAUNCH-SPEC §5 line 158, ADR-032).
 *
 * Status lifecycle is computed by joining the current scan's fingerprints
 * against the prior scan's (pgMemento delta-backed where available, a plain
 * fingerprint-join otherwise — both yield the same set semantics):
 *
 *   - new       — fingerprint present now, never seen in the prior scan AND not
 *                 a re-appearance of a previously fixed finding.
 *   - open      — fingerprint present in both scans (carried over).
 *   - fixed     — fingerprint present in the prior scan, absent now.
 *   - regressed — fingerprint absent in the immediately prior scan but present
 *                 in an earlier (fixed) scan, and present again now.
 *
 * With only a single prior scan available the join collapses to
 * new / open / fixed; `regressed` requires the prior finding's recorded status
 * (a fixed finding that re-appears). We use the prior row's stored status as the
 * regression signal so the join stays a two-scan operation.
 */

import { findingRepo } from '../db/repositories/index.js';
import type { Finding, FindingStatus, ScanId, TenantId } from '../domain/types.js';

/** A computed transition for one fingerprint between prior and current scan. */
export interface StatusTransition {
  readonly fingerprint: string;
  /** The finding row id in the relevant scan (current for new/open/regressed). */
  readonly findingId: string | null;
  readonly from: FindingStatus | null;
  readonly to: FindingStatus;
  /**
   * Display fields carried inline so the diff view renders a real title without
   * depending on the findings tab's client cache (which left every row reading
   * "finding <hash>"). Sourced from the relevant scan's finding row — the current
   * row for new/open/regressed, the prior row for fixed.
   */
  readonly title?: string;
  readonly severity?: string;
  readonly category?: string;
}

/** Pull the display fields off a finding row's `data` JSONB (defensive coercion). */
function displayFields(finding: Finding): Pick<StatusTransition, 'title' | 'severity' | 'category'> {
  const d = (finding.data ?? {}) as Record<string, unknown>;
  const str = (v: unknown): string | undefined => (typeof v === 'string' && v.trim() ? v : undefined);
  const out: { title?: string; severity?: string; category?: string } = {};
  const title = str(d.title);
  if (title) out.title = title;
  const severity = str(d.severity);
  if (severity) out.severity = severity;
  const category = str(d.category);
  if (category) out.category = category;
  return out;
}

/** Aggregate result: transitions plus convenience counts per status. */
export interface DiffResult {
  readonly scanId: ScanId;
  readonly priorScanId: ScanId | null;
  readonly transitions: StatusTransition[];
  readonly counts: Readonly<Record<FindingStatus, number>>;
}

function emptyCounts(): Record<FindingStatus, number> {
  return { new: 0, open: 0, fixed: 0, regressed: 0 };
}

function indexByFingerprint(findings: readonly Finding[]): Map<string, Finding> {
  const map = new Map<string, Finding>();
  for (const f of findings) {
    // Last write wins; a scan should not carry duplicate fingerprints.
    map.set(f.fingerprint, f);
  }
  return map;
}

/**
 * Compute (and persist) the `new|open|fixed|regressed` transitions for a scan
 * relative to its prior scan. When `priorScanId` is null (first scan for the
 * project) every current finding is `new`.
 *
 * Side effect: each current finding's `status` is written via
 * `findingRepo.updateStatus` so the dashboard diff view reads the computed
 * lifecycle directly off the row (ADR-032). `fixed` findings live in the prior
 * scan, so no current row is updated for them.
 */
export async function computeStatusTransitions(
  tenantId: TenantId,
  scanId: ScanId,
  priorScanId: ScanId | null,
): Promise<DiffResult> {
  const current = await findingRepo.listByScan(tenantId, scanId);
  const currentByFp = indexByFingerprint(current);

  const prior = priorScanId ? await findingRepo.listByScan(tenantId, priorScanId) : [];
  const priorByFp = indexByFingerprint(prior);

  const transitions: StatusTransition[] = [];
  const counts = emptyCounts();

  // Walk current findings → new / open / regressed.
  for (const finding of current) {
    const priorRow = priorByFp.get(finding.fingerprint);
    const to = classifyCurrent(priorRow);
    transitions.push({
      fingerprint: finding.fingerprint,
      findingId: finding.id,
      from: priorRow ? priorRow.status : null,
      to,
      ...displayFields(finding),
    });
    counts[to] += 1;
    if (finding.status !== to) {
      await findingRepo.updateStatus(tenantId, finding.id, to);
    }
  }

  // Walk prior findings absent now → fixed.
  for (const priorRow of prior) {
    if (currentByFp.has(priorRow.fingerprint)) continue;
    transitions.push({
      fingerprint: priorRow.fingerprint,
      findingId: priorRow.id,
      from: priorRow.status,
      to: 'fixed',
      ...displayFields(priorRow),
    });
    counts.fixed += 1;
    if (priorRow.status !== 'fixed') {
      await findingRepo.updateStatus(tenantId, priorRow.id, 'fixed');
    }
  }

  return { scanId, priorScanId: priorScanId ?? null, transitions, counts };
}

/**
 * Classify a current-scan finding given its prior-scan counterpart (if any):
 *   - no prior row                → new
 *   - prior row was fixed         → regressed (re-appeared after a fix)
 *   - prior row otherwise present → open (carried over)
 */
function classifyCurrent(priorRow: Finding | undefined): FindingStatus {
  if (!priorRow) return 'new';
  if (priorRow.status === 'fixed') return 'regressed';
  return 'open';
}

/**
 * Pure set-difference variant for callers that only have the two fingerprint
 * lists (e.g. the pgMemento delta path) and want the diff without DB writes.
 * Mirrors the persisted classification minus the `regressed` refinement (which
 * needs the prior row's stored status).
 */
export function diffFingerprints(
  current: readonly string[],
  prior: readonly string[],
): { new: string[]; open: string[]; fixed: string[] } {
  const priorSet = new Set(prior);
  const currentSet = new Set(current);
  return {
    new: current.filter((fp) => !priorSet.has(fp)),
    open: current.filter((fp) => priorSet.has(fp)),
    fixed: prior.filter((fp) => !currentSet.has(fp)),
  };
}
