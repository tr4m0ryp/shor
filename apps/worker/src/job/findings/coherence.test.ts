// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from 'vitest';
import { applyCoherenceGate } from './coherence.js';
import type { FindingRecord } from './types.js';

function rec(over: Partial<FindingRecord> = {}): FindingRecord {
  return {
    id: 'V1',
    validation_note: '',
    title: 'Some Finding',
    category: 'authz',
    cwe: 'CWE-862',
    owasp_category: 'A01',
    severity: 'high',
    confidence: 'confirmed',
    evidence: 'e',
    safe_poc: 'p',
    repro_steps: [],
    vulnerable_code_location: { file: 'A.cs', line: 1 },
    missing_defense: 'd',
    remediation: 'r',
    status: 'new',
    fingerprint: 'fp',
    partialFingerprints: {},
    ...over,
  };
}

describe('coherence gate', () => {
  it('downgrades a confirmed finding that is out of scope', () => {
    const r = rec({ confidence: 'confirmed', in_scope: false });
    expect(applyCoherenceGate([r])).toBe(1);
    expect(r.confidence).toBe('firm');
    expect(r.validation_note).toMatch(/out-of-scope or premise-invalid/i);
  });

  it('downgrades a confirmed finding with a premise that is invalid', () => {
    const r = rec({ confidence: 'confirmed', premise_valid: false });
    applyCoherenceGate([r]);
    expect(r.confidence).toBe('firm');
  });

  it('downgrades a confirmed finding whose cited location was not verified', () => {
    const r = rec({ confidence: 'confirmed', location_verified: false });
    applyCoherenceGate([r]);
    expect(r.confidence).toBe('firm');
    expect(r.validation_note).toMatch(/cited location/i);
  });

  it('caps a critical "InsecureHeaders" finding at medium', () => {
    const r = rec({ severity: 'critical', title: 'InsecureHeaders (Security Misconfiguration)', confidence: 'firm' });
    applyCoherenceGate([r]);
    expect(r.severity).toBe('medium');
    expect(r.validation_note).toMatch(/hardening-only/i);
  });

  it('caps a mislabelled "RequestSmuggling" forwarded-header finding', () => {
    const r = rec({
      severity: 'critical',
      title: 'RequestSmuggling',
      vulnerability_type: 'forwarded header trust',
      confidence: 'firm',
    });
    applyCoherenceGate([r]);
    expect(r.severity).toBe('medium');
  });

  it('leaves a genuine critical (in-scope, real class) untouched', () => {
    const r = rec({ severity: 'critical', title: 'SQL Injection', confidence: 'confirmed', in_scope: true });
    expect(applyCoherenceGate([r])).toBe(0);
    expect(r.severity).toBe('critical');
    expect(r.confidence).toBe('confirmed');
  });
});
