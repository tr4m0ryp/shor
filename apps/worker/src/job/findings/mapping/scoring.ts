// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Confidence / severity scoring, DECOUPLED from disposition (T1).
 *
 * Historically confidence and severity were pure functions of `disposition`
 * (`exploited → confirmed`, auto-escalated severity). That let "exploited the
 * harness mock" and "exploited as the injected god-identity" read as
 * confirmed/critical. These functions take optional EVIDENCE AXES that can only
 * ever DOWN-adjust an over-confident label; they never invent confidence.
 *
 * Back-compat is load-bearing: when `axes` is absent / empty, the output is
 * BYTE-IDENTICAL to the previous `normalizeConfidence` / `inferSeverity` (the
 * existing mapping/gating tests stay green). Axes act ONLY on an `exploited`
 * disposition — the only path that asserts confirmed/critical from disposition
 * alone — and only when an axis is explicitly falsifying (`in_scope === false`
 * OR `premise_valid === false`).
 */

import type { FindingCategory, FindingConfidence, FindingSeverity, VulnDisposition } from '../types.js';

/**
 * Subset of {@link FindingRecord}'s evidence axes that influence scoring. All
 * OPTIONAL: an absent / empty object reproduces the disposition-only behavior.
 */
export interface ScoringAxes {
  /** The target hit is in analyzed scope (not the harness mock / a no-source host). */
  in_scope?: boolean;
  /** The finding's premise holds (a real privilege boundary was crossed, etc.). */
  premise_valid?: boolean;
}

/**
 * True when an axis explicitly FALSIFIES an `exploited` claim: the target was
 * out of scope (`in_scope === false`) or the premise was invalid
 * (`premise_valid === false`). Only a literal `false` falsifies — `undefined`
 * (axis not assessed) preserves today's behavior. An empty / absent `axes`
 * object is never falsifying.
 */
function exploitPremiseFalsified(axes: ScoringAxes | undefined): boolean {
  if (!axes) return false;
  return axes.in_scope === false || axes.premise_valid === false;
}

/**
 * Map a queue confidence + disposition to the §6.1 confidence enum, optionally
 * down-adjusted by evidence axes (T1).
 *
 * Identical to the legacy `normalizeConfidence` when `axes` is absent/empty.
 * When an `exploited` finding is falsified (`in_scope === false` OR
 * `premise_valid === false`) it must NOT read `confirmed`: it drops to
 * `tentative`, which is OUTSIDE the emitted-confirmed set (Task 002 routes it to
 * the appendix via its terminal disposition). Axes only DOWN-adjust.
 */
export function deriveConfidence(value: string, disposition: VulnDisposition, axes?: ScoringAxes): FindingConfidence {
  if (disposition === 'exploited') {
    // A live exploit normally reads `confirmed`. An out-of-scope / invalid-premise
    // exploit proves nothing about the target — refuse to read it as confirmed.
    return exploitPremiseFalsified(axes) ? 'tentative' : 'confirmed';
  }
  // Out-of-scope + unconfirmed: the enforcing tier was never in the analyzed
  // source and nothing live-confirmed it. A screen-rejected hypothesis was
  // actively REFUTED by the adversarial screen. Neither may read as firm/tentative
  // (i.e. "as if seen") — give them the dedicated `unverified` rung. Both are
  // excluded from the emitted set and routed to the manual-review appendix.
  if (disposition === 'unverified_out_of_scope' || disposition === 'unverified_screen_rejected') {
    return 'unverified';
  }
  const v = value.toLowerCase().trim();
  if (v === 'high') return 'firm';
  if (v === 'med' || v === 'medium') return 'firm';
  return 'tentative';
}

/**
 * Infer severity by vulnerability class, escalated when the finding was actually
 * exploited live, optionally down-adjusted by evidence axes (T1). Used ONLY when
 * the analysis queue carried no explicit severity (passed as `explicit`).
 *
 * Most vuln-agent queues (xss/auth/ssrf/authz) omit a severity field entirely —
 * without this fallback every such finding read "medium", masking real
 * critical/high issues (only the injection queue declares `severity_score`).
 *
 * Back-compat: an explicit severity always wins (a queue/human assertion, never
 * disposition-derived), and with no axes the output equals the legacy
 * `explicitSeverity ?? inferSeverity(category, disposition)`. When an `exploited`
 * finding is falsified (`in_scope === false` OR `premise_valid === false`) the
 * disposition escalation is withdrawn: severity returns to its non-escalated base.
 */
export function deriveSeverity(
  category: FindingCategory,
  disposition: VulnDisposition,
  explicit?: FindingSeverity | null,
  axes?: ScoringAxes,
): FindingSeverity {
  if (explicit) return explicit;
  // [baseline, exploited] severity per class.
  const table: Record<FindingCategory, readonly [FindingSeverity, FindingSeverity]> = {
    injection: ['high', 'critical'],
    auth: ['high', 'critical'],
    ssrf: ['medium', 'high'],
    xss: ['medium', 'high'],
    authz: ['medium', 'high'],
    logic: ['medium', 'high'],
    'misconfig-web': ['medium', 'high'],
  };
  const [base, escalated] = table[category];
  const escalate = disposition === 'exploited' && !exploitPremiseFalsified(axes);
  return escalate ? escalated : base;
}
