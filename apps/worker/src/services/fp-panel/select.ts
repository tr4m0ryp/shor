// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Candidate selection for the FP-refute panel (T2): only `confirmed` findings of
 * high impact are worth an adversarial source-aware refute pass. Lower-confidence
 * findings already carry their uncertainty; refuting them buys little and costs voters.
 */

import type { FindingRecord } from '../../job/findings/types.js';

/** Confirmed + (critical|high) findings — the panel's candidate set. */
export function selectFpCandidates(findings: readonly FindingRecord[]): FindingRecord[] {
  return findings.filter(
    (f) => f.confidence === 'confirmed' && (f.severity === 'critical' || f.severity === 'high'),
  );
}
