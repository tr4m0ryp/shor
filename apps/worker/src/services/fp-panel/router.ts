// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Apply the FP-refute panel's verdicts (T2). Every finding the source-aware panel
 * MAJORITY-REFUTED is demoted to the terminal `refuted_on_review` disposition, which
 * `gating.ts isGatedOut` routes to the manual-review appendix.
 *
 * Unlike the screen router, this DOES demote a confirmed/exploited finding — refuting
 * a previously-confirmed false positive is the whole point. Over-reach is bounded
 * because the verdicts file only ever contains confirmed + high/critical candidates.
 * Nothing is deleted; the finding is preserved in the appendix with its reason.
 *
 * This module deliberately does NOT import `job/findings/index` (only the `NormalizedVuln`
 * type + the verdicts IO), so `collectFindings` can import it without an import cycle.
 */

import { canonicalVulnId } from '../../job/findings/evidence.js';
import type { NormalizedVuln } from '../../job/findings/types.js';
import type { ActivityLogger } from '../../types/activity-logger.js';
import { readFpRefutedIds } from './io.js';

/** Id-tolerant lookup mirroring the evidence/oracle lookups (canonical, then trailing-number). */
function lookupRefute(map: Map<string, string>, id: string): string | undefined {
  const canon = canonicalVulnId(id);
  if (map.has(canon)) return map.get(canon);
  const num = canon.match(/(\d+)$/)?.[1];
  if (!num) return undefined;
  for (const [key, reason] of map) {
    if (key.match(/(\d+)$/)?.[1] === num) return reason;
  }
  return undefined;
}

/**
 * Demote every panel-refuted finding to `refuted_on_review`, in place. No-op when no
 * verdicts file exists (the default / panel-off path). Never drops a finding.
 */
export function applyFpRefuteVerdicts(
  vulns: NormalizedVuln[],
  deliverablesPath: string,
  logger: ActivityLogger,
): NormalizedVuln[] {
  const refuted = readFpRefutedIds(deliverablesPath, logger);
  if (refuted.size === 0) return vulns;

  let demoted = 0;
  for (const vuln of vulns) {
    if (vuln.disposition === 'refuted_on_review') continue;
    const reason = lookupRefute(refuted, vuln.id);
    if (reason === undefined) continue;
    vuln.disposition = 'refuted_on_review';
    vuln.evidenceText = vuln.evidenceText
      ? `${vuln.evidenceText}\n\nRefuted on review: ${reason}`
      : `Refuted on review: ${reason}`;
    demoted += 1;
  }
  if (demoted > 0) logger.info('FP-refute panel demoted confirmed findings to manual review', { demoted });
  return vulns;
}
