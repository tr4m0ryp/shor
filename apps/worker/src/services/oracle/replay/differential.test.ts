// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Differential-authz oracle tests (T1): the premise decision table, the
 * auth-header replacement in the executor, the identity-cookie loader, and the
 * end-to-end premise pass through `runOracleReplay`.
 */

import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { httpExecutor } from './executors.js';
import { loadDifferentialIdentities } from './identity-auth.js';
import { runOracleReplay } from './index.js';
import { readPremise } from './poc-io.js';
import { type DifferentialOutcome, decidePremise } from './signal.js';
import type { ExecCtx, ExecOutcome, Poc } from './types.js';

const NOOP = { info() {}, warn() {}, error() {} };
const tmpDirs: string[] = [];
async function mkRoot(): Promise<string> {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'shor-diff-'));
  tmpDirs.push(dir);
  return dir;
}
afterEach(async () => {
  for (const d of tmpDirs.splice(0)) await fsp.rm(d, { recursive: true, force: true });
});

const POC: Poc = { id: 'AUTHZ-VULN-1', kind: 'http', request: { method: 'GET', url: 'http://t/admin' }, expected_signal: { type: 'status', match: 200 } };
const ok: ExecOutcome = { observed: true, status: 200, body: '' };
const forbidden: ExecOutcome = { observed: true, status: 403, body: '' };

describe('decidePremise', () => {
  it('true when a lower AUTHENTICATED identity reproduces the signal', () => {
    const lower: DifferentialOutcome[] = [{ label: 'member', authenticated: true, outcome: ok }];
    expect(decidePremise(POC, lower)).toBe(true);
  });

  it('false when a lower authenticated identity is tried but none reproduce it', () => {
    const lower: DifferentialOutcome[] = [
      { label: 'anonymous', authenticated: false, outcome: { observed: true, status: 401, body: '' } },
      { label: 'member', authenticated: true, outcome: forbidden },
    ];
    expect(decidePremise(POC, lower)).toBe(false);
  });

  it('undefined when only anonymous could be tried and it did not reproduce', () => {
    const lower: DifferentialOutcome[] = [{ label: 'anonymous', authenticated: false, outcome: { observed: true, status: 401, body: '' } }];
    expect(decidePremise(POC, lower)).toBeUndefined();
  });

  it('true when anonymous reproduces it (unauthenticated access)', () => {
    expect(decidePremise(POC, [{ label: 'anonymous', authenticated: false, outcome: ok }])).toBe(true);
  });
});

describe('httpExecutor — differential auth-header replacement', () => {
  function ctxCapturing(captured: { headers: Record<string, string> | undefined }, identity?: ExecCtx['currentIdentity']): ExecCtx {
    return {
      fetchImpl: (async (_url: string, init?: RequestInit) => {
        captured.headers = init?.headers as Record<string, string> | undefined;
        return new Response('', { status: 200 });
      }) as unknown as typeof fetch,
      assertAllowed: () => {},
      timeoutMs: 0,
      logger: NOOP,
      ...(identity ? { currentIdentity: identity } : {}),
    };
  }

  it('strips the PoC captured auth and applies the identity Cookie', async () => {
    const captured: { headers: Record<string, string> | undefined } = { headers: undefined };
    const poc: Poc = { ...POC, request: { method: 'GET', url: 'http://t/admin', headers: { Cookie: 'admin=1', 'X-Trace': 'keep' } } };
    await httpExecutor(poc, ctxCapturing(captured, { label: 'member', headers: { Cookie: 'sess=low' } }));
    expect(captured.headers?.Cookie).toBe('sess=low'); // privileged cookie replaced
    expect(captured.headers?.['X-Trace']).toBe('keep'); // non-auth header preserved
  });

  it('leaves the PoC headers unchanged without an identity (baseline)', async () => {
    const captured: { headers: Record<string, string> | undefined } = { headers: undefined };
    const poc: Poc = { ...POC, request: { method: 'GET', url: 'http://t/admin', headers: { Cookie: 'admin=1' } } };
    await httpExecutor(poc, ctxCapturing(captured));
    expect(captured.headers?.Cookie).toBe('admin=1');
  });
});

describe('loadDifferentialIdentities', () => {
  it('returns anonymous + non-primary identities with cookies, excluding identity-primary', async () => {
    const root = await mkRoot();
    const deliverables = path.join(root, 'deliverables');
    await fsp.mkdir(deliverables, { recursive: true });
    const idRoot = path.join(root, '.playwright-cli', 'identities');
    for (const [dir, cookies] of [
      ['identity-primary', [{ name: 'admin', value: 'x' }]],
      ['identity-member', [{ name: 'sess', value: 'low' }]],
    ] as const) {
      await fsp.mkdir(path.join(idRoot, dir), { recursive: true });
      await fsp.writeFile(path.join(idRoot, dir, 'storage-state.json'), JSON.stringify({ cookies, origins: [] }));
    }
    const ids = loadDifferentialIdentities(deliverables, NOOP);
    expect(ids.map((i) => i.label).sort()).toEqual(['anonymous', 'identity-member']);
    const member = ids.find((i) => i.label === 'identity-member');
    expect(member?.authenticated).toBe(true);
    expect(member?.headers.Cookie).toBe('sess=low');
  });

  it('returns only anonymous when no identities dir exists (fail-open)', async () => {
    const root = await mkRoot();
    const ids = loadDifferentialIdentities(path.join(root, 'deliverables'), NOOP);
    expect(ids).toHaveLength(1);
    expect(ids[0]?.label).toBe('anonymous');
  });
});

describe('runOracleReplay — premise integration', () => {
  it('writes premise_valid=false when a low-priv identity is forbidden', async () => {
    const root = await mkRoot();
    const deliverables = path.join(root, 'deliverables');
    await fsp.mkdir(deliverables, { recursive: true });
    await fsp.writeFile(path.join(deliverables, 'authz_poc.json'), JSON.stringify([POC]));
    const idRoot = path.join(root, '.playwright-cli', 'identities', 'identity-member');
    await fsp.mkdir(idRoot, { recursive: true });
    await fsp.writeFile(path.join(idRoot, 'storage-state.json'), JSON.stringify({ cookies: [{ name: 'sess', value: 'low' }], origins: [] }));

    // Fetch: 200 only when the request carries the member cookie? No — model a real
    // authz gate: member (sess=low) and anonymous both get 403/401 → premise invalid.
    const fetchImpl = (async (_url: string, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      const status = headers.Cookie === 'sess=low' ? 403 : 401;
      return new Response('', { status });
    }) as unknown as typeof fetch;

    await runOracleReplay(deliverables, NOOP, { fetchImpl, assertAllowed: () => {}, delayMs: 0 });
    const premise = readPremise(deliverables, NOOP);
    expect(premise.get('AUTHZ-VULN-1')).toBe(false);
  });
});
