// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * `applyOracleDispositions` calibrated-gating overlay (task 008): the differential
 * premise / authz-matrix / query-log verdicts fold into the WIDENED disposition
 * only when `SHOR_ORACLE_CONFIDENCE=1`; with the flag off it is byte-identical to
 * the historical overlay. Also covers the new signal.ts helpers.
 */

import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { NormalizedVuln } from '../../job/findings/types.js';
import type { ActivityLogger } from '../../types/activity-logger.js';
import { applyOracleDispositions } from './index.js';
import { isInfraOutcome, matchSignal } from './replay/signal.js';
import type { ExecOutcome } from './replay/types.js';

const logger = { info() {}, warn() {}, error() {} } as ActivityLogger;

const tmpDirs: string[] = [];
async function mkDeliverables(): Promise<string> {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'shor-oracle-gate-'));
  tmpDirs.push(dir);
  return dir;
}
afterEach(async () => {
  for (const d of tmpDirs.splice(0)) await fsp.rm(d, { recursive: true, force: true });
});

function vuln(id: string, disposition: NormalizedVuln['disposition']): NormalizedVuln {
  return { category: 'authz', id, raw: { ID: id }, disposition, evidenceText: '' };
}
async function writeJson(dir: string, file: string, obj: unknown): Promise<void> {
  await fsp.writeFile(path.join(dir, file), JSON.stringify(obj));
}

describe('applyOracleDispositions — gating overlay OFF (default) is unchanged', () => {
  it('stamps the premise on raw only, never the typed field (dormant gate)', async () => {
    const dir = await mkDeliverables();
    await writeJson(dir, 'oracle_dispositions.json', { 'AUTHZ-VULN-01': 'not_replayable' });
    await writeJson(dir, 'oracle_premise.json', { 'AUTHZ-VULN-01': false });
    const vulns = [vuln('AUTHZ-VULN-01', 'exploited')];

    applyOracleDispositions(vulns, dir, logger);

    expect(vulns[0]?.disposition).toBe('exploited'); // not_replayable never refutes
    expect(vulns[0]?.raw.premise_valid).toBe(false); // stamped on raw
    expect(vulns[0]?.premise_valid).toBeUndefined(); // typed field left dormant
    expect(vulns[0]?.raw.oracle_replay_disposition).toBeUndefined(); // no widened stamp
  });
});

describe('applyOracleDispositions — gating overlay ON', () => {
  beforeEach(() => {
    process.env.SHOR_ORACLE_CONFIDENCE = '1';
  });
  afterEach(() => {
    delete process.env.SHOR_ORACLE_CONFIDENCE;
  });

  it('infra flake (not_replayable) → inconclusive_infra: persisted, not a refutation', async () => {
    const dir = await mkDeliverables();
    await writeJson(dir, 'oracle_dispositions.json', { 'AUTHZ-VULN-01': 'not_replayable' });
    const vulns = [vuln('AUTHZ-VULN-01', 'exploited')];

    applyOracleDispositions(vulns, dir, logger);

    expect(vulns[0]?.disposition).toBe('exploited'); // fail-open: never demoted
    expect(vulns[0]?.raw.oracle_replay_disposition).toBe('inconclusive_infra');
  });

  it('an invalid premise gates a would-be exploit out of confirmed (needs_review)', async () => {
    const dir = await mkDeliverables();
    await writeJson(dir, 'oracle_dispositions.json', { 'AUTHZ-VULN-01': 'exploited' });
    await writeJson(dir, 'oracle_premise.json', { 'AUTHZ-VULN-01': false });
    const vulns = [vuln('AUTHZ-VULN-01', 'exploited')];

    applyOracleDispositions(vulns, dir, logger);

    expect(vulns[0]?.premise_valid).toBe(false); // typed → premise gate + scoring demote
    expect(vulns[0]?.raw.oracle_replay_disposition).toBe('needs_review');
    expect(typeof vulns[0]?.raw.oracle_confidence).toBe('number');
  });

  it('an authz-matrix bypass verdict promotes a blocked base to exploited', async () => {
    const dir = await mkDeliverables();
    await writeJson(dir, 'oracle_dispositions.json', { 'AUTHZ-VULN-01': 'blocked' });
    await writeJson(dir, 'oracle_authz.json', { 'AUTHZ-VULN-01': 'bypassed' });
    const vulns = [vuln('AUTHZ-VULN-01', 'blocked')];

    applyOracleDispositions(vulns, dir, logger);

    expect(vulns[0]?.disposition).toBe('exploited');
    expect(vulns[0]?.raw.oracle_replay_disposition).toBe('exploited');
  });

  it('an authz-matrix ENFORCED verdict refutes a status-based exploited', async () => {
    const dir = await mkDeliverables();
    await writeJson(dir, 'oracle_dispositions.json', { 'AUTHZ-VULN-01': 'exploited' });
    await writeJson(dir, 'oracle_authz.json', { 'AUTHZ-VULN-01': 'enforced' });
    const vulns = [vuln('AUTHZ-VULN-01', 'exploited')];

    applyOracleDispositions(vulns, dir, logger);

    expect(vulns[0]?.disposition).toBe('blocked');
  });

  it('a query-log injected verdict flows into an exploited disposition', async () => {
    const dir = await mkDeliverables();
    await writeJson(dir, 'oracle_dispositions.json', { 'AUTHZ-VULN-01': 'not_replayable' });
    await writeJson(dir, 'oracle_query_log.json', { 'AUTHZ-VULN-01': 'injected' });
    const vulns = [vuln('AUTHZ-VULN-01', 'blocked')];

    applyOracleDispositions(vulns, dir, logger);

    expect(vulns[0]?.disposition).toBe('exploited');
  });

  it('still promotes a plain exploited replay (behavior preserved under the flag)', async () => {
    const dir = await mkDeliverables();
    await writeJson(dir, 'oracle_dispositions.json', { 'AUTHZ-VULN-01': 'exploited' });
    const vulns = [vuln('AUTHZ-VULN-01', 'blocked')];

    applyOracleDispositions(vulns, dir, logger);

    expect(vulns[0]?.disposition).toBe('exploited');
    expect(vulns[0]?.raw.oracle_replay_disposition).toBe('exploited');
  });
});

describe('signal helpers (T7 integration)', () => {
  it('matchSignal recognizes a sql_log injected verdict', () => {
    const injected: ExecOutcome = { observed: true, sqlLogVerdict: 'injected' };
    const param: ExecOutcome = { observed: true, sqlLogVerdict: 'parameterized' };
    expect(matchSignal({ type: 'sql_log', match: 'x' }, injected)).toBe(true);
    expect(matchSignal({ type: 'sql_log', match: 'x' }, param)).toBe(false);
  });

  it('isInfraOutcome flags every non-observed outcome (never a refutation)', () => {
    expect(isInfraOutcome({ observed: false, reason: 'rate_limited' })).toBe(true);
    expect(isInfraOutcome({ observed: false, reason: 'error' })).toBe(true);
    expect(isInfraOutcome({ observed: false, reason: 'not_replayable' })).toBe(true);
    expect(isInfraOutcome({ observed: true, status: 200 })).toBe(false);
  });
});
