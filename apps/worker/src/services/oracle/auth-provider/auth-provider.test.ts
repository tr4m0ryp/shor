// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * AuthProvider tests (T9): the selector, each provider's ordered candidates +
 * whoami-echo, a failed echo mapping to inconclusive_infra, and the WordPress
 * provider degrading to the prior cookie-only behavior.
 */

import { promises as fsp } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ApiKeyAuthProvider } from './api-key.js';
import { BearerJwtAuthProvider } from './bearer-jwt.js';
import { selectAuthProvider } from './index.js';
import { OidcAuthProvider } from './oidc.js';
import { SessionCookieAuthProvider } from './session-cookie.js';
import type { EchoContext, ProviderIdentity } from './types.js';
import { WordPressAuthProvider } from './wordpress.js';

const NOOP = { info() {}, warn() {}, error() {} };
const tmpDirs: string[] = [];
async function mkRoot(): Promise<string> {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'shor-auth-'));
  tmpDirs.push(dir);
  return dir;
}
afterEach(async () => {
  for (const d of tmpDirs.splice(0)) await fsp.rm(d, { recursive: true, force: true });
  delete process.env.SHOR_AUTH_PROVIDER;
});

/** Write an identity storage-state and return its deliverables path. */
async function seedIdentity(
  dir: string,
  cookies: { name: string; value: string }[],
  origins: { origin: string; localStorage: { name: string; value: string }[] }[] = [],
): Promise<string> {
  const root = await mkRoot();
  const deliverables = path.join(root, 'deliverables');
  await fsp.mkdir(deliverables, { recursive: true });
  const idDir = path.join(root, '.playwright-cli', 'identities', dir);
  await fsp.mkdir(idDir, { recursive: true });
  await fsp.writeFile(path.join(idDir, 'storage-state.json'), JSON.stringify({ cookies, origins }));
  return deliverables;
}

function echoCtx(fetchImpl: typeof fetch): EchoContext {
  return { fetchImpl, assertAllowed: () => {}, timeoutMs: 0, logger: NOOP };
}
function respond(body: string, status = 200): typeof fetch {
  return (async () => new Response(body, { status })) as unknown as typeof fetch;
}
function makeJwt(payload: Record<string, unknown>): string {
  const seg = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${seg({ alg: 'none', typ: 'JWT' })}.${seg(payload)}.sig`;
}

describe('selectAuthProvider', () => {
  it('defaults to the generic session-cookie provider (unchanged behavior)', () => {
    expect(selectAuthProvider().name).toBe('session-cookie');
    expect(selectAuthProvider({ scheme: 'cookie' }).name).toBe('session-cookie');
  });
  it('selects the WordPress provider ONLY for a wordpress platform', () => {
    expect(selectAuthProvider({ platform: 'WordPress' }).name).toBe('wordpress');
    expect(selectAuthProvider({ platform: 'django' }).name).toBe('session-cookie');
  });
  it('maps scheme hints to bearer / oidc / api-key', () => {
    expect(selectAuthProvider({ scheme: 'bearer' }).name).toBe('bearer-jwt');
    expect(selectAuthProvider({ scheme: 'oidc' }).name).toBe('oidc');
    expect(selectAuthProvider({ scheme: 'api-key' }).name).toBe('api-key');
  });
  it('honors an explicit force and the env override seam', () => {
    expect(selectAuthProvider({ scheme: 'cookie', force: 'bearer' }).name).toBe('bearer-jwt');
    process.env.SHOR_AUTH_PROVIDER = 'wordpress';
    expect(selectAuthProvider().name).toBe('wordpress');
    process.env.SHOR_AUTH_PROVIDER = 'nonsense';
    expect(selectAuthProvider().name).toBe('session-cookie');
  });
});

describe('SessionCookieAuthProvider', () => {
  it('acquires non-primary cookie identities and offers a single cookie candidate', async () => {
    const deliverables = await seedIdentity('identity-member', [{ name: 'sess', value: 'low' }]);
    // Also seed the primary dir to prove it is excluded.
    const idRoot = path.join(path.dirname(deliverables), '.playwright-cli', 'identities', 'identity-primary');
    await fsp.mkdir(idRoot, { recursive: true });
    await fsp.writeFile(path.join(idRoot, 'storage-state.json'), JSON.stringify({ cookies: [{ name: 'a', value: 'b' }], origins: [] }));

    const provider = new SessionCookieAuthProvider();
    const ids = provider.acquireIdentities({ deliverablesPath: deliverables, logger: NOOP });
    expect(ids.map((i) => i.label)).toEqual(['identity-member']);
    const cands = provider.authCandidates(ids[0] as ProviderIdentity);
    expect(cands.map((c) => c.kind)).toEqual(['cookie']);
    expect(cands[0]?.headers.Cookie).toBe('sess=low');
  });

  it('echo: matched principal → confirmed; wrong body → inconclusive_infra', async () => {
    const provider = new SessionCookieAuthProvider({ whoamiUrl: 'http://t/me' });
    const id: ProviderIdentity = {
      label: 'member',
      authenticated: true,
      principal: { label: 'member', runtimeTokens: ['alice'] },
      candidates: [{ kind: 'cookie', durability: 20, headers: { Cookie: 'x' } }],
    };
    const ok = await provider.whoamiEcho(id, id.candidates[0]!, echoCtx(respond('{"user":"alice"}')));
    expect(ok.status).toBe('confirmed');
    const bad = await provider.whoamiEcho(id, id.candidates[0]!, echoCtx(respond('{"user":"bob"}')));
    expect(bad).toEqual({ status: 'inconclusive_infra', reason: 'mismatch' });
  });

  it('echo without an endpoint is inconclusive_infra (never blocked)', async () => {
    const provider = new SessionCookieAuthProvider();
    const id: ProviderIdentity = {
      label: 'member',
      authenticated: true,
      principal: { label: 'member' },
      candidates: [{ kind: 'cookie', durability: 20, headers: {} }],
    };
    const res = await provider.whoamiEcho(id, id.candidates[0]!, echoCtx(respond('anything')));
    expect(res).toEqual({ status: 'inconclusive_infra', reason: 'no_endpoint' });
  });

  it('echo: a 403 (logged out) is inconclusive_infra, not a refutation', async () => {
    const provider = new SessionCookieAuthProvider({ whoamiUrl: 'http://t/me' });
    const id: ProviderIdentity = {
      label: 'member',
      authenticated: true,
      principal: { label: 'member', runtimeTokens: ['alice'] },
      candidates: [{ kind: 'cookie', durability: 20, headers: {} }],
    };
    const res = await provider.whoamiEcho(id, id.candidates[0]!, echoCtx(respond('', 403)));
    expect(res.status).toBe('inconclusive_infra');
  });
});

describe('BearerJwtAuthProvider', () => {
  it('acquires a JWT from localStorage and echoes its claims locally (no round-trip)', async () => {
    const jwt = makeJwt({ sub: 'alice', preferred_username: 'alice' });
    const deliverables = await seedIdentity('identity-user', [], [
      { origin: 'http://t', localStorage: [{ name: 'access_token', value: jwt }] },
    ]);
    const provider = new BearerJwtAuthProvider();
    const ids = provider.acquireIdentities({ deliverablesPath: deliverables, logger: NOOP });
    expect(ids).toHaveLength(1);
    const id: ProviderIdentity = { ...(ids[0] as ProviderIdentity), principal: { label: 'x', runtimeTokens: ['alice'] } };
    const cand = provider.authCandidates(id)[0]!;
    expect(cand.kind).toBe('bearer');
    expect(cand.headers.Authorization).toBe(`Bearer ${jwt}`);
    // Local claim echo confirms without the fetch ever firing.
    const throwFetch = (() => {
      throw new Error('network must not be used');
    }) as unknown as typeof fetch;
    const res = await provider.whoamiEcho(id, cand, echoCtx(throwFetch));
    expect(res.status).toBe('confirmed');
  });

  it('a non-matching claim falls through to inconclusive_infra', async () => {
    const jwt = makeJwt({ sub: 'someoneelse' });
    const provider = new BearerJwtAuthProvider();
    const id: ProviderIdentity = {
      label: 'x',
      authenticated: true,
      principal: { label: 'x', runtimeTokens: ['alice'] },
      candidates: [{ kind: 'bearer', durability: 60, headers: { Authorization: `Bearer ${jwt}` } }],
    };
    const res = await provider.whoamiEcho(id, id.candidates[0]!, echoCtx(respond('', 401)));
    expect(res.status).toBe('inconclusive_infra');
  });

  it('OIDC tags its candidate as oidc-bearer', async () => {
    const jwt = makeJwt({ sub: 'alice' });
    const deliverables = await seedIdentity('identity-user', [], [
      { origin: 'http://t', localStorage: [{ name: 'id_token', value: jwt }] },
    ]);
    const provider = new OidcAuthProvider();
    const ids = provider.acquireIdentities({ deliverablesPath: deliverables, logger: NOOP });
    expect(provider.authCandidates(ids[0] as ProviderIdentity)[0]?.kind).toBe('oidc-bearer');
  });
});

describe('WordPressAuthProvider', () => {
  it('degrades to cookie-only when no WP credentials are configured (no regression)', async () => {
    const deliverables = await seedIdentity('identity-member', [{ name: 'wordpress_logged_in', value: 'x' }]);
    const provider = new WordPressAuthProvider({ origin: 'http://wp' });
    const ids = provider.acquireIdentities({ deliverablesPath: deliverables, logger: NOOP });
    const cands = provider.authCandidates(ids[0] as ProviderIdentity);
    expect(cands.map((c) => c.kind)).toEqual(['cookie']);
  });

  it('orders app-password > cookie+nonce > cookie and reauth walks the list', async () => {
    const deliverables = await seedIdentity('identity-member', [{ name: 'wordpress_logged_in', value: 'x' }]);
    const provider = new WordPressAuthProvider({
      origin: 'http://wp',
      identityAuth: { 'identity-member': { appPasswordBasic: 'YWJj', restNonce: 'n0nce', principalTokens: ['editor'] } },
    });
    const id = provider.acquireIdentities({ deliverablesPath: deliverables, logger: NOOP })[0] as ProviderIdentity;
    const ordered = provider.authCandidates(id);
    expect(ordered.map((c) => c.kind)).toEqual(['app-password', 'cookie+csrf', 'cookie']);
    // reauth self-heal steps to the next-most-durable candidate, then exhausts.
    const next = provider.reauth(id, ordered[0]!);
    expect(next?.kind).toBe('cookie+csrf');
    expect(provider.reauth(id, ordered[2]!)).toBeUndefined();
  });

  it('echoes against the wp-json users/me endpoint built from origin', async () => {
    const provider = new WordPressAuthProvider({ origin: 'http://wp/' });
    const id: ProviderIdentity = {
      label: 'identity-member',
      authenticated: true,
      principal: { label: 'identity-member', runtimeTokens: ['editor'] },
      candidates: [{ kind: 'cookie', durability: 20, headers: { Cookie: 'x' } }],
    };
    let called = '';
    const fetchImpl = (async (url: string) => {
      called = url;
      return new Response('{"slug":"editor"}', { status: 200 });
    }) as unknown as typeof fetch;
    const res = await provider.whoamiEcho(id, id.candidates[0]!, echoCtx(fetchImpl));
    expect(called).toBe('http://wp/wp-json/wp/v2/users/me?context=edit');
    expect(res.status).toBe('confirmed');
  });
});

describe('ApiKeyAuthProvider', () => {
  it('builds a header-key candidate from config and echoes via the whoami endpoint', async () => {
    const provider = new ApiKeyAuthProvider({
      apiKeyHeader: 'X-Api-Key',
      whoamiUrl: 'http://t/me',
      identities: [{ label: 'svc', key: 'secret-key', principalTokens: ['svc-account'] }],
    });
    const id = provider.acquireIdentities({ deliverablesPath: '/nope', logger: NOOP })[0] as ProviderIdentity;
    const cand = provider.authCandidates(id)[0]!;
    expect(cand.kind).toBe('api-key');
    expect(cand.headers['X-Api-Key']).toBe('secret-key');
    const res = await provider.whoamiEcho(id, cand, echoCtx(respond('{"name":"svc-account"}')));
    expect(res.status).toBe('confirmed');
  });
});
