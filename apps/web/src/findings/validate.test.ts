// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Finding-validation tests (LAUNCH-SPEC §6.1, ADR-030).
 *
 * Focuses on the OPTIONAL precision fields the worker may attach
 * (reachability / cluster_id / oracle_disposition / threat_id): they must be
 * accepted when present-and-valid, ignored when absent (back-compat), and
 * rejected when present with an out-of-range value.
 */

import { describe, expect, it } from 'vitest';
import { assertValidFindings, FindingValidationError, validateFinding } from './validate.js';

/** A minimal §6.1-valid record: only the always-required identity + enum fields. */
function baseFinding(): Record<string, unknown> {
  return {
    id: 'F-001',
    category: 'xss',
    cwe: 'CWE-79',
    owasp_category: 'A03:2021-Injection',
    severity: 'high',
    confidence: 'firm',
  };
}

describe('validateFinding — optional precision fields', () => {
  it('accepts a record carrying all four new fields with valid values', () => {
    const finding = {
      ...baseFinding(),
      reachability: 'REACHABLE',
      cluster_id: 'cluster-7',
      oracle_disposition: 'exploited',
      threat_id: 'threat-42',
    };
    expect(validateFinding(finding, 0)).toEqual([]);
  });

  it('still accepts a record that omits every new field (back-compat)', () => {
    expect(validateFinding(baseFinding(), 0)).toEqual([]);
  });

  it('rejects an out-of-range reachability value', () => {
    const finding = { ...baseFinding(), reachability: 'SOMETIMES' };
    const issues = validateFinding(finding, 0);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.field).toBe('reachability');
    expect(() => assertValidFindings([finding])).toThrow(FindingValidationError);
  });

  it('rejects an out-of-range oracle_disposition value', () => {
    const finding = { ...baseFinding(), oracle_disposition: 'maybe' };
    const issues = validateFinding(finding, 0);
    expect(issues.some((issue) => issue.field === 'oracle_disposition')).toBe(true);
  });
});
