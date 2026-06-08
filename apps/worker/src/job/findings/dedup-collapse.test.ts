// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from 'vitest';
import { clusterDeterministic, collapseClusters, dedupAndCollapse } from './dedup-collapse.js';
import type { FindingRecord, FindingSeverity } from './types.js';

function rec(id: string, over: Partial<FindingRecord> = {}): FindingRecord {
  return {
    id,
    validation_note: '',
    title: `Finding ${id}`,
    category: 'ssrf',
    cwe: 'CWE-918',
    owasp_category: 'A10',
    severity: 'high',
    confidence: 'firm',
    evidence: 'e',
    safe_poc: 'p',
    repro_steps: [],
    vulnerable_code_location: { file: 'EffectService.cs', line: 211 },
    missing_defense: 'd',
    remediation: 'r',
    status: 'new',
    fingerprint: `fp-${id}`,
    partialFingerprints: { 'locationCwe/v1': 'SAME' },
    ...over,
  };
}

describe('dedup-collapse', () => {
  it('collapses 5 records sharing a location+CWE to 1 with 4 folded into also_reported_as', () => {
    const sevs: FindingSeverity[] = ['high', 'critical', 'medium', 'high', 'low'];
    const records = sevs.map((s, i) => rec(`V${i}`, { severity: s, title: `SSRF framing ${i}` }));
    const out = dedupAndCollapse(records);
    expect(out).toHaveLength(1);
    const [rep] = out;
    expect(rep?.severity).toBe('critical'); // representative = highest severity
    expect(rep?.also_reported_as).toHaveLength(4);
  });

  it('preserves every member (no loss): representative + also_reported_as == input', () => {
    const records = [rec('A'), rec('B'), rec('C')];
    const out = dedupAndCollapse(records);
    const accountedFor = 1 + (out[0]!.also_reported_as?.length ?? 0);
    expect(accountedFor).toBe(records.length);
  });

  it('leaves a singleton (distinct location+CWE) untouched', () => {
    const a = rec('A', { partialFingerprints: { 'locationCwe/v1': 'K1' } });
    const b = rec('B', { partialFingerprints: { 'locationCwe/v1': 'K2' }, vulnerable_code_location: { file: 'Other.cs', line: 9 } });
    const out = dedupAndCollapse([a, b]);
    expect(out).toHaveLength(2);
    expect(out.every((r) => r.also_reported_as === undefined)).toBe(true);
  });

  it('preserves a cluster_id already assigned by the LLM judge', () => {
    const a = rec('A', { cluster_id: 'cl_judge', partialFingerprints: { 'locationCwe/v1': 'X' } });
    const b = rec('B', { cluster_id: 'cl_judge', partialFingerprints: { 'locationCwe/v1': 'Y' } });
    // Same judge cluster_id despite different partial fingerprints ⇒ still collapses to 1.
    const out = collapseClusters(clusterDeterministic([a, b]));
    expect(out).toHaveLength(1);
  });
});
