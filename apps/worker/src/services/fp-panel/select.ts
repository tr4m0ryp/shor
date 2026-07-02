// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Candidate selection for the FP-refute panel (T2): only `confirmed` findings of
 * high impact are worth an adversarial source-aware refute pass. Lower-confidence
 * findings already carry their uncertainty; refuting them buys little and costs voters.
 */

import type { FindingRecord } from '../../job/findings/types.js';

/** Confirmed + (critical|high) findings — the panel's candidate set. */
export function selectFpCandidates(findings: readonly FindingRecord[]): FindingRecord[] {
  return findings.filter((f) => f.confidence === 'confirmed' && (f.severity === 'critical' || f.severity === 'high'));
}
