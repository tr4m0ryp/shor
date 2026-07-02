// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Scoring-decouple regression tests (T1).
 *
 * The contract these lock in:
 *   1. BYTE-IDENTICAL back-compat — with no axes (today's callers), the new
 *      `deriveConfidence` / `deriveSeverity` reproduce the legacy
 *      `normalizeConfidence` / `inferSeverity` for every disposition + class.
 *   2. Axes only ever DOWN-adjust an `exploited` claim: `in_scope === false` or
 *      `premise_valid === false` stops it reading confirmed/critical. Anything
 *      else (axes assessed true, or only `code_confirmed`/etc. present) is inert.
 */

import { describe, expect, it } from 'vitest';
import type { FindingCategory, FindingConfidence, FindingSeverity, VulnDisposition } from '../types.js';
import { deriveConfidence, deriveSeverity } from './scoring.js';

const CATEGORIES: FindingCategory[] = ['injection', 'xss', 'auth', 'ssrf', 'authz', 'logic', 'misconfig-web'];

const DISPOSITIONS: VulnDisposition[] = [
  'exploited',
  'blocked',
  'queued',
  'screen_uncertain',
  'unverified_out_of_scope',
  'unverified_screen_rejected',
];

// --- Legacy reference implementations (verbatim from the pre-split mapping.ts) ---

function legacyConfidence(value: string, disposition: VulnDisposition): FindingConfidence {
  if (disposition === 'exploited') return 'confirmed';
  if (disposition === 'unverified_out_of_scope' || disposition === 'unverified_screen_rejected') {
    return 'unverified';
  }
  const v = value.toLowerCase().trim();
  if (v === 'high') return 'firm';
  if (v === 'med' || v === 'medium') return 'firm';
  return 'tentative';
}

function legacySeverity(category: FindingCategory, disposition: VulnDisposition): FindingSeverity {
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
  return disposition === 'exploited' ? escalated : base;
}

describe('deriveConfidence — back-compat (no axes)', () => {
  const values = ['high', 'HIGH', 'med', 'medium', 'low', '', 'garbage'];
  it('matches the legacy normalizeConfidence for every disposition × value', () => {
    for (const disposition of DISPOSITIONS) {
      for (const value of values) {
        expect(deriveConfidence(value, disposition)).toBe(legacyConfidence(value, disposition));
        // An empty axes object must behave exactly like "no axes".
        expect(deriveConfidence(value, disposition, {})).toBe(legacyConfidence(value, disposition));
      }
    }
  });
});

describe('deriveSeverity — back-compat (no axes)', () => {
  it('matches the legacy inferSeverity for every category × disposition', () => {
    for (const category of CATEGORIES) {
      for (const disposition of DISPOSITIONS) {
        expect(deriveSeverity(category, disposition)).toBe(legacySeverity(category, disposition));
        expect(deriveSeverity(category, disposition, null, {})).toBe(legacySeverity(category, disposition));
      }
    }
  });

  it('an explicit severity always wins and is untouched by axes', () => {
    expect(deriveSeverity('xss', 'exploited', 'low')).toBe('low');
    expect(deriveSeverity('injection', 'exploited', 'low', { in_scope: false })).toBe('low');
    expect(deriveSeverity('auth', 'queued', 'critical', { premise_valid: false })).toBe('critical');
  });
});

describe('deriveConfidence — axes DOWN-adjust an exploited finding', () => {
  it('in_scope=false stops an exploited finding reading confirmed', () => {
    expect(deriveConfidence('high', 'exploited')).toBe('confirmed');
    const downgraded = deriveConfidence('high', 'exploited', { in_scope: false });
    expect(downgraded).not.toBe('confirmed');
    expect(downgraded).toBe('tentative');
  });

  it('premise_valid=false stops an exploited finding reading confirmed', () => {
    expect(deriveConfidence('high', 'exploited', { premise_valid: false })).toBe('tentative');
  });

  it('axes assessed TRUE leave an exploited finding confirmed (never invent doubt)', () => {
    expect(
      deriveConfidence('high', 'exploited', {
        in_scope: true,
        premise_valid: true,
      }),
    ).toBe('confirmed');
  });

  it('axes never UP-adjust a non-exploited finding', () => {
    // A queued finding with positive axes stays at its value-derived rung.
    expect(deriveConfidence('low', 'queued', { in_scope: true, premise_valid: true })).toBe('tentative');
    // And a falsifying axis on a non-exploited finding does not change it either.
    expect(deriveConfidence('high', 'blocked', { in_scope: false })).toBe(legacyConfidence('high', 'blocked'));
  });
});

describe('deriveSeverity — axes withdraw the exploited escalation', () => {
  it('in_scope=false returns the non-escalated base severity', () => {
    expect(deriveSeverity('injection', 'exploited')).toBe('critical');
    expect(deriveSeverity('injection', 'exploited', null, { in_scope: false })).toBe('high');
  });

  it('premise_valid=false returns the non-escalated base severity', () => {
    expect(deriveSeverity('xss', 'exploited', null, { premise_valid: false })).toBe('medium');
  });

  it('positive axes keep the exploited escalation', () => {
    expect(
      deriveSeverity('auth', 'exploited', null, {
        in_scope: true,
        premise_valid: true,
      }),
    ).toBe('critical');
  });
});
