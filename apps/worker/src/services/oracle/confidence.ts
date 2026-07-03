// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Calibrated, GATING proof-confidence (spec T7 / F3 / F4) — the piece Ali records
 * but never gates on. Two responsibilities, both PURE (no IO, no clock):
 *
 *  1. {@link computeConfidence} — an ORTHOGONAL-AXIS score. Each axis kills a
 *     distinct false-positive class (whoami-confirmed, a real negative control,
 *     an anon-floor that stayed clean, an OOB callback, auth-durability; minus
 *     retry-flakiness and a query-log FP-demotion). A hard falsifier
 *     (`in_scope === false` / `premise_valid === false`) fails CLOSED to the
 *     floor. The raw axis probability is then run through a calibration fitted to
 *     P(true-positive) on the task-017 labeled corpus.
 *
 *  2. {@link combineVerdict} — fold the base replay disposition with the new
 *     proof signals (authz-matrix, query-log, OOB) into the WIDENED disposition
 *     ({@link ReplayDisposition}). Promotion is fail-CLOSED (a low score → the
 *     wider `needs_review`, never a silent `exploited`); demotion is fail-OPEN
 *     (an infra outcome → `inconclusive_infra`, NEVER a refutation).
 *
 * Calibration honesty: the seed corpus is a 12-sample, deliberately adversarial
 * fixture (its high-confidence items are ~50% analyst-confirmed-but-wrong). A fit on
 * it degenerates to the base rate — so we DETECT that, fall back to identity, and set
 * {@link CALIBRATION}.recalibrationNeeded. The orthogonal axes carry the real signal.
 */

import type { FindingConfidence } from '../../job/findings/types.js';
import { toCalibrationSamples } from '../measurement/benchmark/index.js';
import type { AuthzVerdict } from './replay/authz-matrix.js';
import type { OracleDisposition, ReplayDisposition } from './replay/types.js';
import type { QueryLogVerdict } from './query-log/types.js';

/** Master flag: the whole calibrated-gating overlay is OFF unless this is set. */
export const ORACLE_CONFIDENCE_ENV = 'SHOR_ORACLE_CONFIDENCE';

/** True when the calibrated gating overlay is enabled (default OFF → stock behavior). */
export function oracleConfidenceEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env[ORACLE_CONFIDENCE_ENV] === '1';
}

/** Below this calibrated P(true-positive), a would-be `exploited` gates to needs_review. */
export const NEEDS_REVIEW_THRESHOLD = 0.5;

/** The floor a hard-falsified claim collapses to (fail-closed). */
const FALSIFIED_SCORE = 0.05;

/** Orthogonal axis weights, in log-odds. Each targets a distinct FP class (F3/F4). */
const W = {
  whoami: 0.7, // proved we fired AS the intended principal (not silently logged out)
  negControl: 0.7, // a real negative control ran (rules out "everything 200s")
  anonClean: 0.9, // the anon floor did NOT reproduce (rules out "it is just public")
  oob: 1.6, // a witnessed out-of-band callback (blind-class proof)
  authDurable: 0.5, // auth held across the replay
  flake: 1.5, // penalty coefficient × retry-flakiness fraction
  fpDemotion: 1.6, // query-log said "parameterized" (safe) — strong demotion
} as const;

/** Categorical §6.1 confidence → prior P(true-positive) (matches the 017 corpus prior). */
const LABEL_PRIOR: Record<FindingConfidence, number> = {
  confirmed: 0.9,
  firm: 0.6,
  tentative: 0.35,
  unverified: 0.1,
};

/** Replay disposition → prior P(true-positive) used when no categorical label is known. */
const DISPOSITION_PRIOR: Record<OracleDisposition, number> = {
  exploited: 0.9,
  blocked: 0.2,
  not_replayable: 0.3,
};

/** Prior for a categorical confidence label. */
export function labelPrior(label: FindingConfidence): number {
  return LABEL_PRIOR[label];
}

/** Prior for a base replay disposition (the oracle's own proof-strength prior). */
export function dispositionPrior(disposition: OracleDisposition): number {
  return DISPOSITION_PRIOR[disposition];
}

const clamp01 = (n: number): number => (!Number.isFinite(n) ? 0 : n < 0 ? 0 : n > 1 ? 1 : n);
const sigmoid = (x: number): number => 1 / (1 + Math.exp(-x));
const logit = (p: number): number => {
  const q = Math.min(1 - 1e-6, Math.max(1e-6, p));
  return Math.log(q / (1 - q));
};

/** Fitted calibration metadata (temperature scaling on the 017 corpus). */
export interface CalibrationFit {
  /** Fitted temperature (>1 softens overconfidence). */
  readonly temperature: number;
  /** Whether the fit is actually applied (false ⇒ identity fallback). */
  readonly applied: boolean;
  /** True when the seed corpus was too small/degenerate to trust — expand it. */
  readonly recalibrationNeeded: boolean;
  readonly samples: number;
  readonly baseRate: number;
}

/** Temperature past which we treat the fit as degenerate (it just flattens to base rate). */
const DEGENERATE_T = 6;

/**
 * Fit a temperature by grid-minimizing log-loss of `sigmoid(logit(p)/T)` over the
 * labeled samples. If the fit does not positively separate TP from FP, or T is
 * degenerate, fall back to identity and flag that recalibration is needed.
 */
function fitCalibration(samples: readonly { predicted: number; label: 0 | 1 }[]): CalibrationFit {
  const n = samples.length;
  const baseRate = n > 0 ? samples.reduce((a, s) => a + s.label, 0) / n : 0;
  if (n < 20) {
    // Corpus too small to trust a curve — identity, flag for expansion.
    return { temperature: 1, applied: false, recalibrationNeeded: true, samples: n, baseRate };
  }
  let bestT = 1;
  let bestLoss = Number.POSITIVE_INFINITY;
  for (let t = 0.25; t <= DEGENERATE_T; t += 0.05) {
    let loss = 0;
    for (const s of samples) {
      const q = Math.min(1 - 1e-9, Math.max(1e-9, sigmoid(logit(s.predicted) / t)));
      loss += -(s.label * Math.log(q) + (1 - s.label) * Math.log(1 - q));
    }
    if (loss / n < bestLoss) {
      bestLoss = loss / n;
      bestT = t;
    }
  }
  // Does the fit positively separate the classes? (mean-cal on TP must exceed FP).
  let tpSum = 0;
  let tpN = 0;
  let fpSum = 0;
  let fpN = 0;
  for (const s of samples) {
    const q = sigmoid(logit(s.predicted) / bestT);
    if (s.label === 1) {
      tpSum += q;
      tpN += 1;
    } else {
      fpSum += q;
      fpN += 1;
    }
  }
  const separates = tpN > 0 && fpN > 0 && tpSum / tpN - fpSum / fpN > 0.05;
  const usable = separates && bestT < DEGENERATE_T - 1e-9;
  return {
    temperature: usable ? bestT : 1,
    applied: usable,
    recalibrationNeeded: !usable,
    samples: n,
    baseRate,
  };
}

/** The calibration fitted once, at module load, against the task-017 labeled corpus. */
export const CALIBRATION: CalibrationFit = fitCalibration(toCalibrationSamples());

/** Apply the fitted calibration to a raw probability. Identity when not applied. */
export function calibrate(raw: number, fit: CalibrationFit = CALIBRATION): number {
  if (!fit.applied) return clamp01(raw);
  return clamp01(sigmoid(logit(raw) / fit.temperature));
}

/** Orthogonal confidence axes. All OPTIONAL: undefined ⇒ that axis is not assessed. */
export interface ConfidenceAxes {
  /** whoami/identity-echo confirmed we fired as the intended principal. */
  whoamiConfirmed?: boolean;
  /** A real negative control ran (symmetric-peer leg / self-noise floor present). */
  negativeControlPresent?: boolean;
  /** The anonymous floor did NOT reproduce (not merely a public resource). */
  anonFloorClean?: boolean;
  /** A witnessed out-of-band callback fired (blind-class proof). */
  oobConfirmed?: boolean;
  /** Auth held across the replay (the identity did not silently drop). */
  authDurable?: boolean;
  /** Retry-flakiness fraction in [0,1] (how flaky the replay was). */
  retryFlakiness?: number;
  /** Query-log proved the payload was safely parameterized (FP-demotion). */
  fpDemotion?: boolean;
  /** Hard falsifier — the target hit is out of analyzed scope. */
  inScope?: boolean;
  /** Hard falsifier — no real privilege boundary was crossed (premise invalid). */
  premiseValid?: boolean;
}

/** A calibrated score plus its gating decision. */
export interface ConfidenceResult {
  /** Calibrated P(true-positive) in [0,1]. */
  readonly score: number;
  /** `needs_review` when the score is below {@link NEEDS_REVIEW_THRESHOLD}. */
  readonly gate: 'ok' | 'needs_review';
  /** True when a hard falsifier collapsed the score to the floor. */
  readonly falsified: boolean;
}

/** +w when the axis is true, −w/2 when explicitly false, 0 when unassessed. */
function bump(axis: boolean | undefined, weight: number): number {
  if (axis === true) return weight;
  if (axis === false) return -weight / 2;
  return 0;
}

/**
 * Compute the calibrated, gating confidence from a base prior + orthogonal axes.
 * A hard falsifier fails CLOSED to the floor (→ needs_review). Otherwise the axes
 * adjust the base log-odds and the result is calibrated to the 017 corpus.
 */
export function computeConfidence(basePrior: number, axes: ConfidenceAxes = {}): ConfidenceResult {
  if (axes.inScope === false || axes.premiseValid === false) {
    return { score: FALSIFIED_SCORE, gate: 'needs_review', falsified: true };
  }
  let l = logit(clamp01(basePrior));
  l += bump(axes.whoamiConfirmed, W.whoami);
  l += bump(axes.negativeControlPresent, W.negControl);
  l += bump(axes.anonFloorClean, W.anonClean);
  l += bump(axes.oobConfirmed, W.oob);
  l += bump(axes.authDurable, W.authDurable);
  // Query-log "parameterized" is a one-directional FP-demotion (never a promotion).
  if (axes.fpDemotion === true) l -= W.fpDemotion;
  if (typeof axes.retryFlakiness === 'number') l -= W.flake * clamp01(axes.retryFlakiness);
  const score = calibrate(sigmoid(l));
  return { score, gate: score < NEEDS_REVIEW_THRESHOLD ? 'needs_review' : 'ok', falsified: false };
}

/** All proof signals folded by {@link combineVerdict}. */
export interface VerdictSignals {
  /** The base replay verdict from the executable oracle. */
  readonly base: OracleDisposition;
  /** Differential-authz premise (T1): `false` ⇒ no privilege boundary crossed. */
  readonly premiseValid?: boolean;
  /** Four-way authz-matrix verdict (005), when the matrix ran. */
  readonly authz?: AuthzVerdict;
  /** SQL query-log verdict (007), when the oracle ran. */
  readonly queryLog?: QueryLogVerdict;
  /** A witnessed OOB callback fired (006). */
  readonly oobObserved?: boolean;
  /** Fraction of replays that flaked (drives the flakiness penalty). */
  readonly retryFlakiness?: number;
  /** Out-of-analyzed-scope hard falsifier. */
  readonly inScope?: boolean;
}

/** The widened, gated verdict + its calibrated score. */
export interface CombinedVerdict {
  readonly disposition: ReplayDisposition;
  readonly score: number;
  readonly gate: 'ok' | 'needs_review';
}

/**
 * Fold the base disposition with the authz-matrix / query-log / OOB signals into
 * the widened {@link ReplayDisposition}, applying the fail-open / fail-closed rule:
 *   - a positive proof (base exploited, OOB callback, authz `bypassed`, query-log
 *     `injected`) confirms — but promotion is fail-CLOSED behind the gate: a low
 *     calibrated score returns `needs_review`, never a silent `exploited`;
 *   - a `not_replayable` base with no positive proof is `inconclusive_infra` —
 *     NEVER a refutation (fail-open on demotion);
 *   - a genuine negative control (base `blocked`, authz `enforced`, query-log
 *     `parameterized`) demotes to `blocked`.
 */
export function combineVerdict(signals: VerdictSignals): CombinedVerdict {
  const axes: ConfidenceAxes = {
    ...(signals.premiseValid !== undefined && { premiseValid: signals.premiseValid }),
    ...(signals.oobObserved !== undefined && { oobConfirmed: signals.oobObserved }),
    ...(signals.retryFlakiness !== undefined && { retryFlakiness: signals.retryFlakiness }),
    ...(signals.inScope !== undefined && { inScope: signals.inScope }),
    // A `bypassed` matrix decided on body-ownership across a real 4-way control.
    ...(signals.authz === 'bypassed' && { anonFloorClean: true, negativeControlPresent: true }),
    ...(signals.authz === 'enforced' && { negativeControlPresent: true }),
    ...(signals.queryLog === 'parameterized' && { fpDemotion: true }),
  };

  // The white-box authz matrix (body-ownership) DOMINATES a naive status replay: an
  // `enforced` verdict refutes a status-based `exploited` for that finding.
  const authzRefutes = signals.authz === 'enforced';
  const confirmedByProof =
    signals.oobObserved === true || signals.authz === 'bypassed' || signals.queryLog === 'injected';
  const confirmed = confirmedByProof || (signals.base === 'exploited' && !authzRefutes);

  const prior = confirmed ? dispositionPrior('exploited') : dispositionPrior(signals.base);
  const { score, gate } = computeConfidence(prior, axes);

  if (confirmed) {
    // Fail-closed promotion: a low score holds the claim for review, never emits it.
    return { disposition: gate === 'needs_review' ? 'needs_review' : 'exploited', score, gate };
  }
  // A genuine negative control demotes to `blocked`; anything else inconclusive.
  const genuineNegative = signals.base === 'blocked' || authzRefutes || signals.queryLog === 'parameterized';
  if (genuineNegative) return { disposition: 'blocked', score, gate };
  // Fail-open: an infra / not-replayable / unknown outcome NEVER refutes a finding.
  return { disposition: 'inconclusive_infra', score, gate };
}
