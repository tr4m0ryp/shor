// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
