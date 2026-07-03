// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Integration tests for the OOB executor + the interactsh sidecar listener:
 * config gating (default-off), placeholder injection, the network-guard seam,
 * proof vs inconclusive verdicts, and JSONL base-domain detection + buffered
 * correlation over an injected (no-real-binary) sidecar.
 */

import { EventEmitter } from 'node:events';
import { afterEach, describe, expect, it } from 'vitest';
import type { ActivityLogger } from '../../../../types/activity-logger.js';
import type { ExecCtx, Poc } from '../types.js';
import type { SpawnFn } from './index.js';
import { createOobExecutor, mintToken, readOobConfig, startInteractshListener } from './index.js';
import type { OobConfig, OobInteraction, OobListener } from './types.js';
import { OOB_CALLBACK_PLACEHOLDER } from './types.js';

const NOOP: ActivityLogger = { info() {}, warn() {}, error() {} };
const CORR = 'abcdefghij0123456789';
const BASE_LABEL = `${CORR}klmnopqrstuvw`;
const BASE = `${BASE_LABEL}.oast.example.net`;
const NONCE = 'deadbeefdeadbeef';

function ctx(over: Partial<ExecCtx> = {}): ExecCtx {
  return {
    fetchImpl: (async () => new Response('')) as unknown as typeof fetch,
    assertAllowed: () => {},
    timeoutMs: 1_000,
    logger: NOOP,
    ...over,
  };
}

function oobPoc(over: Partial<Poc> = {}): Poc {
  return {
    id: 'SSRF-VULN-01',
    kind: 'oob',
    request: { method: 'GET', url: `https://t.example/fetch?u=http://${OOB_CALLBACK_PLACEHOLDER}/p` },
    expected_signal: { type: 'oob', match: 'callback' },
    safe: true,
    ...over,
  };
}

function fakeListener(over: Partial<OobListener> = {}): OobListener {
  return {
    ready: true,
    baseDomain: () => BASE,
    awaitCallback: async () => null,
    stop: async () => {},
    ...over,
  };
}

const hit: OobInteraction = {
  protocol: 'dns',
  correlationId: CORR,
  labels: new Set([NONCE]),
  remoteAddress: '203.0.113.9',
  timestamp: '2026-07-03T00:00:00Z',
};

describe('readOobConfig (default-off gating)', () => {
  const KEYS = ['SHOR_OOB', 'SHOR_INTERACTSH_SERVER', 'SHOR_OOB_WINDOW_MS', 'SHOR_OOB_POLL_MS'];
  const saved: Record<string, string | undefined> = {};
  afterEach(() => {
    for (const k of KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });
  function set(env: Record<string, string>): void {
    for (const k of KEYS) saved[k] = process.env[k];
    for (const k of KEYS) delete process.env[k];
    for (const [k, v] of Object.entries(env)) process.env[k] = v;
  }

  it('returns undefined unless SHOR_OOB=1 AND a self-hosted server is set', () => {
    set({});
    expect(readOobConfig()).toBeUndefined();
    set({ SHOR_OOB: '1' });
    expect(readOobConfig()).toBeUndefined();
    set({ SHOR_INTERACTSH_SERVER: 'oast.example.net' });
    expect(readOobConfig()).toBeUndefined();
  });

  it('builds config with a LONG default window when fully enabled', () => {
    set({ SHOR_OOB: '1', SHOR_INTERACTSH_SERVER: 'oast.example.net' });
    const cfg = readOobConfig();
    expect(cfg?.server).toBe('oast.example.net');
    expect(cfg?.clientBin).toBe('interactsh-client');
    expect(cfg?.windowMs).toBeGreaterThanOrEqual(30_000);
    expect(cfg?.pollMs).toBeGreaterThan(0);
  });

  it('honors window/poll overrides', () => {
    set({
      SHOR_OOB: '1',
      SHOR_INTERACTSH_SERVER: 'oast.example.net',
      SHOR_OOB_WINDOW_MS: '90000',
      SHOR_OOB_POLL_MS: '500',
    });
    const cfg = readOobConfig();
    expect(cfg?.windowMs).toBe(90_000);
    expect(cfg?.pollMs).toBe(500);
  });
});

describe('createOobExecutor', () => {
  it('is not_replayable when no listener / not ready (OOB disabled)', async () => {
    const off = createOobExecutor(undefined);
    expect((await off(oobPoc(), ctx())).observed).toBe(false);
    const notReady = createOobExecutor(fakeListener({ ready: false }));
    expect((await notReady(oobPoc(), ctx())).observed).toBe(false);
  });

  it('is not_replayable when the PoC has no {{OOB_CALLBACK}} placeholder', async () => {
    const exec = createOobExecutor(fakeListener());
    const out = await exec(oobPoc({ request: { method: 'GET', url: 'https://t.example/x' } }), ctx());
    expect(out).toMatchObject({ observed: false, reason: 'not_replayable' });
  });

  it('injects the minted host (guard + fetch see NO placeholder) and CONFIRMS on a witnessed callback', async () => {
    let guarded = '';
    let fired = '';
    const exec = createOobExecutor(fakeListener({ awaitCallback: async () => hit }), { nonce: NONCE });
    const out = await exec(
      oobPoc(),
      ctx({
        assertAllowed: (u) => {
          guarded = u;
        },
        fetchImpl: (async (u: string) => {
          fired = String(u);
          return new Response('');
        }) as unknown as typeof fetch,
      }),
    );
    expect(out).toEqual({ observed: true, oobObserved: true });
    expect(guarded).not.toContain(OOB_CALLBACK_PLACEHOLDER);
    expect(fired).not.toContain(OOB_CALLBACK_PLACEHOLDER);
    expect(fired).toContain(BASE);
    expect(fired).toContain(NONCE);
  });

  it('is INCONCLUSIVE (not blocked) when no witnessed callback arrives in the window', async () => {
    const exec = createOobExecutor(fakeListener({ awaitCallback: async () => null }), { nonce: NONCE });
    const out = await exec(oobPoc(), ctx());
    expect(out).toMatchObject({ observed: false, reason: 'not_replayable' });
    expect((out as { detail?: string }).detail).toMatch(/no witnessed OOB callback/);
  });

  it('degrades to not_replayable when the network guard blocks the injected URL', async () => {
    const exec = createOobExecutor(fakeListener({ awaitCallback: async () => hit }), { nonce: NONCE });
    const out = await exec(
      oobPoc(),
      ctx({
        assertAllowed: () => {
          throw new Error('egress blocked');
        },
      }),
    );
    expect(out).toMatchObject({ observed: false, reason: 'not_replayable' });
  });

  it('does not refute when the fired request itself errors (blind class)', async () => {
    const exec = createOobExecutor(fakeListener({ awaitCallback: async () => hit }), { nonce: NONCE });
    const out = await exec(
      oobPoc(),
      ctx({
        fetchImpl: (async () => {
          throw new Error('connection refused');
        }) as unknown as typeof fetch,
      }),
    );
    expect(out).toEqual({ observed: true, oobObserved: true });
  });
});

/** A minimal stand-in for the interactsh-client child process. */
class FakeStdout extends EventEmitter {
  setEncoding(): void {}
}
class FakeChild extends EventEmitter {
  readonly stdout = new FakeStdout();
  killed = false;
  kill(): boolean {
    this.killed = true;
    return true;
  }
}

function line(sub: string): string {
  return `${JSON.stringify({
    protocol: 'dns',
    'unique-id': CORR,
    'full-id': sub,
    'raw-request': `;${sub}.oast.example.net. IN A`,
    'remote-address': '203.0.113.9',
    timestamp: '2026-07-03T00:00:00Z',
  })}\n`;
}

describe('startInteractshListener (JSONL sidecar over an injected spawn)', () => {
  const cfg: OobConfig = {
    server: 'oast.example.net',
    clientBin: 'interactsh-client',
    windowMs: 5_000,
    pollMs: 1,
  };

  it('detects the base domain, buffers a witnessed interaction, and resolves awaitCallback', async () => {
    let child!: FakeChild;
    const spawnFake: SpawnFn = (() => {
      child = new FakeChild();
      return child;
    }) as unknown as SpawnFn;
    const listener = startInteractshListener(cfg, NOOP, spawnFake);

    // Banner line printed by the client at startup → base domain becomes known.
    child.stdout.emit('data', `[INF] Listing 1 payload for OOB Testing\n${BASE}\n`);
    expect(listener.ready).toBe(true);
    expect(listener.baseDomain()).toBe(BASE);

    const token = mintToken(listener.baseDomain() ?? '', 'SSRF-VULN-01\nGET x\n', NONCE);
    child.stdout.emit('data', line(`${NONCE}.${token.witness}.${BASE_LABEL}`));

    let clock = 0;
    const found = await listener.awaitCallback(token, {
      windowMs: 5_000,
      pollMs: 1,
      now: () => clock,
      sleep: async () => {
        clock += 1;
      },
    });
    expect(found).not.toBeNull();
    expect(found?.correlationId).toBe(CORR);
    await listener.stop();
    expect(child.killed).toBe(true);
  });

  it('returns null after the long window when no matching callback arrives', async () => {
    let child!: FakeChild;
    const spawnFake: SpawnFn = (() => {
      child = new FakeChild();
      return child;
    }) as unknown as SpawnFn;
    const listener = startInteractshListener(cfg, NOOP, spawnFake);
    child.stdout.emit('data', `${BASE}\n`);

    const token = mintToken(BASE, 'seed\n', NONCE);
    let clock = 0;
    const found = await listener.awaitCallback(token, {
      windowMs: 10,
      pollMs: 5,
      now: () => clock,
      sleep: async () => {
        clock += 5;
      },
    });
    expect(found).toBeNull();
  });
});
