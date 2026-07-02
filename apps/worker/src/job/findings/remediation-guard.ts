// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Boilerplate-remediation guard (T7).
 *
 * The mapper emits a TEMPLATE remediation when no real fix prose exists:
 *   "Apply the missing defense: <X>. See the attack-surface deliverable ..."
 *   "Apply the context-correct <category> defense; see the attack-surface deliverable ..."
 * The finalize improver is supposed to replace it with a line-specific fix. This
 * detects a remediation that is STILL the template (or empty) so finalize can FLAG it
 * — a finding must never ship as confirmed with non-actionable boilerplate silently.
 */

import type { FindingRecord } from './types.js';

const BOILERPLATE_PATTERNS: readonly RegExp[] = [
  /^\s*apply the missing defense:.*see the attack-surface deliverable/is,
  /^\s*apply the context-correct .* defense; see the attack-surface deliverable/is,
];

/**
 * True when `text` is the mapper's template remediation, or empty/whitespace (also
 * non-actionable). A real, rewritten remediation returns false.
 */
export function isBoilerplateRemediation(text: string | undefined | null): boolean {
  if (typeof text !== 'string' || text.trim() === '') return true;
  return BOILERPLATE_PATTERNS.some((re) => re.test(text));
}

/**
 * Flag every record whose remediation is still boilerplate (sets
 * `remediation_boilerplate=true` via the record index signature). Returns the count
 * flagged. Mutates in place; never drops or rewrites the finding.
 */
export function flagBoilerplateRemediation(records: FindingRecord[]): number {
  let flagged = 0;
  for (const rec of records) {
    if (isBoilerplateRemediation(rec.remediation)) {
      rec.remediation_boilerplate = true;
      flagged += 1;
    }
  }
  return flagged;
}
