// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * FP-refute panel tests (T2): candidate selection (confirmed + high/critical only)
 * and the verdict router (a majority-refute demotes the finding to
 * `refuted_on_review`; support/uncertain leave it; nothing is dropped).
 */

import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { FindingRecord, NormalizedVuln } from '../../job/findings/types.js';
import type { ScreenVerdictEntry } from '../screen-panel/index.js';
import { writeFpVerdicts } from './io.js';
import { applyFpRefuteVerdicts } from './router.js';
import { selectFpCandidates } from './select.js';

const NOOP = { info() {}, warn() {}, error() {} };
const tmpDirs: string[] = [];
async function mkRoot(): Promise<string> {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'shor-fp-'));
  tmpDirs.push(dir);
  return dir;
}
afterEach(async () => {
  for (const d of tmpDirs.splice(0)) await fsp.rm(d, { recursive: true, force: true });
});

function rec(over: Partial<FindingRecord>): FindingRecord {
  return {
    id: 'AUTHZ-VULN-1',
    validation_note: '',
    title: 't',
    category: 'authz',
    cwe: 'CWE-862',
    owasp_category: 'A01',
    severity: 'critical',
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

function vuln(over: Partial<NormalizedVuln>): NormalizedVuln {
  return { category: 'authz', id: 'AUTHZ-VULN-1', raw: {}, disposition: 'exploited', evidenceText: '', ...over };
}

function entry(id: string, decision: ScreenVerdictEntry['decision'], reason = 'r'): ScreenVerdictEntry {
  return { id, votes: [{ voter: 1, lens: 'control-sanitizer', verdict: decision, reason }], decision };
}

describe('selectFpCandidates', () => {
  it('keeps only confirmed + critical/high findings', () => {
    const findings = [
      rec({ id: 'A', confidence: 'confirmed', severity: 'critical' }),
      rec({ id: 'B', confidence: 'confirmed', severity: 'high' }),
      rec({ id: 'C', confidence: 'confirmed', severity: 'medium' }), // wrong severity
      rec({ id: 'D', confidence: 'firm', severity: 'critical' }), // wrong confidence
    ];
    expect(selectFpCandidates(findings).map((f) => f.id)).toEqual(['A', 'B']);
  });
});

describe('applyFpRefuteVerdicts', () => {
  it('demotes a refuted finding to refuted_on_review (even when exploited)', async () => {
    const root = await mkRoot();
    writeFpVerdicts(root, [entry('AUTHZ-VULN-1', 'refute', 'guard present at Users.cs:46')], NOOP);
    const vulns = [vuln({ id: 'AUTHZ-VULN-1', disposition: 'exploited' })];
    applyFpRefuteVerdicts(vulns, root, NOOP);
    expect(vulns[0]?.disposition).toBe('refuted_on_review');
    expect(vulns[0]?.evidenceText).toMatch(/Refuted on review: guard present/);
  });

  it('leaves support/uncertain findings untouched', async () => {
    const root = await mkRoot();
    writeFpVerdicts(root, [entry('AUTHZ-VULN-1', 'support'), entry('AUTHZ-VULN-2', 'uncertain')], NOOP);
    const vulns = [vuln({ id: 'AUTHZ-VULN-1' }), vuln({ id: 'AUTHZ-VULN-2' })];
    applyFpRefuteVerdicts(vulns, root, NOOP);
    expect(vulns.every((v) => v.disposition === 'exploited')).toBe(true);
  });

  it('is a no-op when no verdicts file exists', async () => {
    const root = await mkRoot();
    const vulns = [vuln({ id: 'AUTHZ-VULN-1' })];
    applyFpRefuteVerdicts(vulns, root, NOOP);
    expect(vulns[0]?.disposition).toBe('exploited');
  });
});
