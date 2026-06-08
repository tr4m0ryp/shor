// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Coherence gate (T8) — the last invariant check before the emitted/appendix split.
 *
 * Runs AFTER mapping, on `FindingRecord`s, and DEMOTES (never deletes) any record
 * whose label outruns its evidence:
 *   - `confirmed` requires `in_scope !== false` AND `premise_valid !== false`;
 *     otherwise the confidence is dropped to `firm` (a confirmed scaffolding /
 *     privileged-only finding is not a confirmation).
 *   - `confirmed` with `location_verified === false` (the cited file:line did NOT
 *     contain the construct) is dropped to `firm` — a mis-cited finding is not confirmed.
 *   - `critical`/`high` on a hardening-only weakness class (missing security
 *     headers, forwarded-header trust, mis-labelled "request smuggling", verbose
 *     error/log disclosure) is capped at `medium` — these are not critical on their own.
 * Every demotion appends a short reason to `validation_note` so the dashboard shows WHY.
 */

import type { FindingRecord, FindingSeverity } from './types.js';

/**
 * Weakness phrasings that are hardening / defense-in-depth only — never critical on
 * their own. Matched against the title + raw `vulnerability_type`. Conservative: it
 * targets the specific inflation seen in practice (missing headers, forwarded-header
 * trust, the "request smuggling" mislabel, verbose-error disclosure), not real
 * misconfig criticals (e.g. an auth bypass also lives in the misconfig class).
 */
const HARDENING_ONLY =
  /insecure.?header|missing.?(security.?)?header|\bhsts\b|\bcsp\b|x-frame|clickjack|forwarded.?header|transport exposure|request.?smuggling|verbose error|stack trace/i;

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Cap a severity at `medium` (only lowers; never raises). */
function capAtMedium(sev: FindingSeverity): FindingSeverity {
  return SEVERITY_RANK[sev] < SEVERITY_RANK.medium ? 'medium' : sev;
}

function isHardeningOnly(rec: FindingRecord): boolean {
  const type = typeof rec.vulnerability_type === 'string' ? rec.vulnerability_type : '';
  return HARDENING_ONLY.test(rec.title) || HARDENING_ONLY.test(type);
}

/** Append a reason to a record's validation_note without clobbering existing prose. */
function note(rec: FindingRecord, reason: string): void {
  rec.validation_note = rec.validation_note ? `${rec.validation_note} ${reason}` : reason;
}

/**
 * Apply the coherence invariants in place. Returns the number of records demoted
 * (for logging). Never drops a record — callers keep emitting/appendixing as before.
 */
export function applyCoherenceGate(records: FindingRecord[]): number {
  let demoted = 0;
  for (const rec of records) {
    let changed = false;

    // A `confirmed` finding must be in-scope, premise-valid, and not mis-cited.
    if (rec.confidence === 'confirmed') {
      if (rec.in_scope === false || rec.premise_valid === false) {
        rec.confidence = 'firm';
        note(rec, 'Coherence: downgraded from confirmed — finding is out-of-scope or premise-invalid.');
        changed = true;
      } else if (rec.location_verified === false) {
        rec.confidence = 'firm';
        note(rec, 'Coherence: downgraded from confirmed — cited location did not contain the construct.');
        changed = true;
      }
    }

    // Hardening-only weaknesses are not critical/high on their own.
    if ((rec.severity === 'critical' || rec.severity === 'high') && isHardeningOnly(rec)) {
      const capped = capAtMedium(rec.severity);
      if (capped !== rec.severity) {
        rec.severity = capped;
        note(rec, 'Coherence: severity capped at medium — hardening-only weakness, not critical alone.');
        changed = true;
      }
    }

    if (changed) demoted += 1;
  }
  return demoted;
}
