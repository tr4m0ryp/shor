// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * `toFindingRecord` integration tests for the Task 001 wiring: evidence axes flow
 * from the normalized vuln onto the record and DOWN-adjust an over-confident
 * exploited finding end-to-end; the new optional axis fields are absent (not
 * `false`/`undefined`-stamped) on the back-compat path; `cwe_inferred` is set only
 * on a category-default fallback; and `location_verified` is stamped only when an
 * analyzed-source root is supplied (fail-open otherwise).
 */

import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { NormalizedVuln } from '../types.js';
import { toFindingRecord } from './record.js';

const tmpDirs: string[] = [];
async function mkRoot(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'shor-record-'));
  tmpDirs.push(dir);
  return dir;
}
afterEach(async () => {
  for (const d of tmpDirs.splice(0)) {
    await fs.rm(d, { recursive: true, force: true });
  }
});

function vuln(over: Partial<NormalizedVuln> & { raw?: Record<string, unknown> }): NormalizedVuln {
  return {
    category: 'authz',
    id: 'AUTHZ-VULN-1',
    raw: {},
    disposition: 'exploited',
    evidenceText: '',
    ...over,
  };
}

describe('toFindingRecord — back-compat (no axes on the vuln)', () => {
  it('an exploited finding reads confirmed and stamps no axis fields', () => {
    const r = toFindingRecord(
      vuln({
        category: 'injection',
        disposition: 'exploited',
        raw: { vulnerability_type: 'sqli', sink_call: 'db.query:42' },
      }),
    );
    expect(r.confidence).toBe('confirmed');
    expect(r.severity).toBe('critical');
    // New optional axis fields must be ABSENT (not present-as-undefined) so the
    // emitted record is byte-identical to the pre-Task-001 shape.
    expect('in_scope' in r).toBe(false);
    expect('premise_valid' in r).toBe(false);
    expect('location_verified' in r).toBe(false);
  });
});

describe('toFindingRecord — axes DOWN-adjust an exploited finding end-to-end', () => {
  it('in_scope=false demotes confidence off confirmed and withdraws escalation', () => {
    const base = vuln({
      category: 'injection',
      disposition: 'exploited',
      raw: { vulnerability_type: 'sqli', sink_call: 'db.query:42', confidence: 'high' },
    });
    const confirmed = toFindingRecord(base);
    expect(confirmed.confidence).toBe('confirmed');
    expect(confirmed.severity).toBe('critical');

    const downgraded = toFindingRecord({ ...base, in_scope: false });
    expect(downgraded.confidence).not.toBe('confirmed');
    expect(downgraded.confidence).toBe('tentative');
    expect(downgraded.severity).toBe('high'); // non-escalated base
    expect(downgraded.in_scope).toBe(false); // axis carried onto the record

    // Identity is preserved — the downgrade must not move the fingerprint.
    expect(downgraded.fingerprint).toBe(confirmed.fingerprint);
  });

  it('premise_valid=false also demotes an exploited finding', () => {
    const r = toFindingRecord(
      vuln({
        category: 'authz',
        disposition: 'exploited',
        premise_valid: false,
        raw: { vulnerability_type: 'vertical', endpoint: '/admin' },
      }),
    );
    expect(r.confidence).toBe('tentative');
    expect(r.premise_valid).toBe(false);
  });
});

describe('toFindingRecord — per-finding CWE (T4)', () => {
  it('sets cwe_inferred on a category-default fallback', () => {
    const r = toFindingRecord(vuln({ category: 'authz', raw: { vulnerability_type: 'some bespoke rule' } }));
    expect(r.cwe).toBe('CWE-862');
    expect(r.cwe_inferred).toBe(true);
  });

  it('does NOT set cwe_inferred when a mechanism CWE matched', () => {
    const r = toFindingRecord(
      vuln({ category: 'authz', raw: { vulnerability_type: 'Horizontal IDOR', endpoint: '/x' } }),
    );
    expect(r.cwe).toBe('CWE-639');
    expect('cwe_inferred' in r).toBe(false);
  });
});

describe('toFindingRecord — cite-line verification (T5)', () => {
  it('does not stamp location_verified without a source root', () => {
    const r = toFindingRecord(
      vuln({ category: 'xss', raw: { sink_function: 'view.ts:2', vulnerability_type: 'renderTemplate xss' } }),
    );
    expect('location_verified' in r).toBe(false);
  });

  it('stamps location_verified=true when the construct is at the cited line', async () => {
    const root = await mkRoot();
    await fs.writeFile(
      path.join(root, 'view.ts'),
      `${['function h(req){', '  return renderTemplate(req.q);', '}'].join('\n')}\n`,
    );
    const r = toFindingRecord(
      vuln({
        category: 'xss',
        raw: { sink_function: 'view.ts:2', vulnerability_type: 'renderTemplate reflected' },
      }),
      { analyzedSourceRoot: root },
    );
    expect(r.location_verified).toBe(true);
  });
});

describe('toFindingRecord — code_confirmed (T3, derived from cite-line verify)', () => {
  it('stamps code_confirmed=true when the cited line verifies', async () => {
    const root = await mkRoot();
    await fs.writeFile(
      path.join(root, 'view.ts'),
      `${['function h(req){', '  return renderTemplate(req.q);', '}'].join('\n')}\n`,
    );
    const r = toFindingRecord(
      vuln({ category: 'xss', raw: { sink_function: 'view.ts:2', vulnerability_type: 'renderTemplate reflected' } }),
      { analyzedSourceRoot: root },
    );
    expect(r.code_confirmed).toBe(true);
  });

  it('does NOT stamp code_confirmed without a source root (fail-open)', () => {
    const r = toFindingRecord(
      vuln({ category: 'xss', raw: { sink_function: 'view.ts:2', vulnerability_type: 'renderTemplate xss' } }),
    );
    expect('code_confirmed' in r).toBe(false);
  });

  it('does NOT stamp code_confirmed on a mis-cite (location_verified=false)', async () => {
    const root = await mkRoot();
    await fs.writeFile(path.join(root, 'boot.ts'), `${['const v = 1;', 'export const X = 2;'].join('\n')}\n`);
    const r = toFindingRecord(
      vuln({ category: 'injection', raw: { sink_call: 'boot.ts:2', vulnerability_type: 'executeRawQuery sqli' } }),
      { analyzedSourceRoot: root },
    );
    expect(r.location_verified).toBe(false);
    expect('code_confirmed' in r).toBe(false);
  });
});
