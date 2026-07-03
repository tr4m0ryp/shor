// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Calibrated gating-confidence tests (T7): the orthogonal-axis score, the gate, and
 * the widened-disposition combination (fail-open on demotion / fail-closed on
 * promotion; inconclusive_infra is never a refutation).
 */

import { describe, expect, it } from 'vitest';
import {
  CALIBRATION,
  combineVerdict,
  computeConfidence,
  dispositionPrior,
  NEEDS_REVIEW_THRESHOLD,
  oracleConfidenceEnabled,
} from './confidence.js';

describe('oracleConfidenceEnabled (flag gate)', () => {
  it('is off unless SHOR_ORACLE_CONFIDENCE=1', () => {
    expect(oracleConfidenceEnabled({})).toBe(false);
    expect(oracleConfidenceEnabled({ SHOR_ORACLE_CONFIDENCE: '0' })).toBe(false);
    expect(oracleConfidenceEnabled({ SHOR_ORACLE_CONFIDENCE: '1' })).toBe(true);
  });
});

describe('CALIBRATION (fitted against the 017 seed corpus)', () => {
  it('flags recalibration: the 12-sample adversarial seed is too small/degenerate', () => {
    // The seed corpus is deliberately miscalibrated (its high-confidence items are
    // ~50% analyst-confirmed-but-wrong), so a curve fit degenerates — we fall back
    // to identity and flag it, rather than ship a bogus calibration.
    expect(CALIBRATION.recalibrationNeeded).toBe(true);
    expect(CALIBRATION.applied).toBe(false);
    expect(CALIBRATION.samples).toBe(12);
  });
});

describe('computeConfidence — orthogonal axes gate the score', () => {
  it('a clean exploited prior with no axes stays above the review gate', () => {
    const r = computeConfidence(dispositionPrior('exploited'));
    expect(r.gate).toBe('ok');
    expect(r.score).toBeGreaterThan(NEEDS_REVIEW_THRESHOLD);
    expect(r.falsified).toBe(false);
  });

  it('a hard falsifier (premise invalid) fails CLOSED to the floor → needs_review', () => {
    const r = computeConfidence(dispositionPrior('exploited'), { premiseValid: false });
    expect(r.falsified).toBe(true);
    expect(r.gate).toBe('needs_review');
    expect(r.score).toBeLessThan(NEEDS_REVIEW_THRESHOLD);
  });

  it('out-of-scope also fails CLOSED', () => {
    expect(computeConfidence(0.9, { inScope: false }).gate).toBe('needs_review');
  });

  it('an OOB callback lifts confidence', () => {
    const withOob = computeConfidence(dispositionPrior('exploited'), { oobConfirmed: true });
    const without = computeConfidence(dispositionPrior('exploited'));
    expect(withOob.score).toBeGreaterThanOrEqual(without.score);
    expect(withOob.gate).toBe('ok');
  });

  it('a weak (tentative) prior with no corroboration gates to needs_review', () => {
    expect(computeConfidence(0.35).gate).toBe('needs_review');
  });

  it('retry-flakiness lowers the score', () => {
    const flaky = computeConfidence(0.9, { retryFlakiness: 1 });
    const clean = computeConfidence(0.9);
    expect(flaky.score).toBeLessThan(clean.score);
  });

  it('a query-log FP-demotion lowers the score', () => {
    const demoted = computeConfidence(0.9, { fpDemotion: true });
    expect(demoted.score).toBeLessThan(computeConfidence(0.9).score);
  });
});

describe('combineVerdict — signals flow into the widened disposition', () => {
  it('a plain exploited base → exploited', () => {
    expect(combineVerdict({ base: 'exploited' }).disposition).toBe('exploited');
  });

  it('an infra flake (not_replayable) → inconclusive_infra, never blocked', () => {
    const v = combineVerdict({ base: 'not_replayable' });
    expect(v.disposition).toBe('inconclusive_infra');
    expect(v.disposition).not.toBe('blocked');
  });

  it('a low-confidence exploit (premise invalid) → needs_review, not silently exploited', () => {
    const v = combineVerdict({ base: 'exploited', premiseValid: false });
    expect(v.disposition).toBe('needs_review');
    expect(v.gate).toBe('needs_review');
  });

  it('OOB callback promotes even a blocked-looking base (fail-open promotion via proof)', () => {
    expect(combineVerdict({ base: 'blocked', oobObserved: true }).disposition).toBe('exploited');
  });

  it('a four-way authz bypass confirms a cross-user leak', () => {
    expect(combineVerdict({ base: 'not_replayable', authz: 'bypassed' }).disposition).toBe('exploited');
  });

  it('an authz-matrix ENFORCED verdict refutes a naive status-based exploited', () => {
    // The body-ownership matrix dominates the status replay.
    expect(combineVerdict({ base: 'exploited', authz: 'enforced' }).disposition).toBe('blocked');
  });

  it('query-log INJECTED confirms blind injection', () => {
    expect(combineVerdict({ base: 'not_replayable', queryLog: 'injected' }).disposition).toBe('exploited');
  });

  it('query-log PARAMETERIZED demotes a would-be blind injection to blocked', () => {
    expect(combineVerdict({ base: 'not_replayable', queryLog: 'parameterized' }).disposition).toBe('blocked');
  });

  it('query-log PARAMETERIZED only lowers confidence of an already-proven exploit', () => {
    const v = combineVerdict({ base: 'exploited', queryLog: 'parameterized' });
    expect(v.disposition).toBe('exploited'); // demote-don't-delete
    expect(v.score).toBeLessThan(combineVerdict({ base: 'exploited' }).score);
  });

  it('a genuine blocked base stays blocked', () => {
    expect(combineVerdict({ base: 'blocked' }).disposition).toBe('blocked');
  });

  it('authz UNKNOWN never refutes (fail-open) — inconclusive, not blocked', () => {
    expect(combineVerdict({ base: 'not_replayable', authz: 'unknown' }).disposition).toBe('inconclusive_infra');
  });
});
