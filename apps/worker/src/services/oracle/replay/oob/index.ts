// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * OOB proof module root (spec T8, F14, R6): the `oob` executor the oracle wiring
 * (task 008) drops into `DEFAULT_EXECUTORS.oob`, plus the public surface.
 *
 * Per attempt the executor: mints a fresh witnessed callback host under the live
 * interactsh session, substitutes it for the `{{OOB_CALLBACK}}` placeholder in
 * the PoC request, fires the request through the network guard (the TARGET makes
 * the callback, not us), then waits a LONG window for a boundary-safe witnessed
 * callback. A witnessed callback ⇒ `observed + oobObserved` (proof). No callback
 * in the window ⇒ `not_replayable` (INCONCLUSIVE, never a `blocked` refutation:
 * blind classes fail-open on demotion; a second-order callback may still arrive).
 *
 * This module builds the OOB path only; it does NOT wire it — 008 owns the seam.
 */

import type { ExecCtx, ExecOutcome, Executor, Poc, PocRequest } from '../types.js';
import { mintToken } from './correlate.js';
import type { AwaitOptions, OobListener } from './types.js';
import { OOB_CALLBACK_PLACEHOLDER } from './types.js';

/** Auth headers replaced wholesale when firing under a differential identity. */
const AUTH_HEADERS: ReadonlySet<string> = new Set(['authorization', 'cookie']);

/** A `not_replayable` outcome — the OOB path is inconclusive, never a refutation. */
function inconclusive(detail: string): ExecOutcome {
  return { observed: false, reason: 'not_replayable', detail };
}

/** Does the PoC request carry the OOB callback placeholder anywhere? */
function hasPlaceholder(req: PocRequest): boolean {
  if (req.url.includes(OOB_CALLBACK_PLACEHOLDER)) return true;
  if (req.body?.includes(OOB_CALLBACK_PLACEHOLDER)) return true;
  for (const v of Object.values(req.headers ?? {})) {
    if (v.includes(OOB_CALLBACK_PLACEHOLDER)) return true;
  }
  return false;
}

/** Replace every placeholder occurrence with the minted callback host. */
function injectCallback(req: PocRequest, host: string): PocRequest {
  const sub = (s: string): string => s.split(OOB_CALLBACK_PLACEHOLDER).join(host);
  const out: PocRequest = { method: req.method, url: sub(req.url) };
  if (req.headers) {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) headers[k] = sub(v);
    out.headers = headers;
  }
  if (req.body !== undefined) out.body = sub(req.body);
  return out;
}

/**
 * The witness seed binds the token to THIS exact fired payload (finding id +
 * method + url + body). A different payload ⇒ a different witness label, so a
 * callback for one payload can never be mistaken as proof of another.
 */
function witnessSeedFor(poc: Poc, req: PocRequest): string {
  return `${poc.id}\n${req.method.toUpperCase()} ${req.url}\n${req.body ?? ''}`;
}

/** Merge the PoC headers with a differential identity's auth (strip captured auth). */
function resolveHeaders(
  pocHeaders: Record<string, string> | undefined,
  identityHeaders: Record<string, string> | undefined,
): Record<string, string> | undefined {
  if (!identityHeaders) return pocHeaders;
  const stripped: Record<string, string> = {};
  for (const [k, v] of Object.entries(pocHeaders ?? {})) {
    if (!AUTH_HEADERS.has(k.toLowerCase())) stripped[k] = v;
  }
  const merged = { ...stripped, ...identityHeaders };
  return Object.keys(merged).length > 0 ? merged : undefined;
}

/**
 * Fire the OOB-injected request best-effort. We do NOT care about the direct
 * response (blind class); a transport error is swallowed so it never refutes.
 * DNS-first: even if the target's HTTP egress is filtered, its DNS lookup of the
 * injected host still reaches interactsh.
 */
async function fireRequest(req: PocRequest, ctx: ExecCtx): Promise<void> {
  const method = (req.method ?? 'GET').toUpperCase();
  const headers = resolveHeaders(req.headers, ctx.currentIdentity?.headers);
  const controller = new AbortController();
  const timer = ctx.timeoutMs > 0 ? setTimeout(() => controller.abort(), ctx.timeoutMs) : undefined;
  try {
    await ctx.fetchImpl(req.url, {
      method,
      ...(headers && { headers }),
      ...(req.body !== undefined && method !== 'GET' && method !== 'HEAD' && { body: req.body }),
      signal: controller.signal,
    });
  } catch {
    // Blind proof: the callback is the signal, not this response. Ignore errors.
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Options controlling the OOB executor built by {@link createOobExecutor}. */
export interface OobExecutorOptions {
  /** Injectable nonce for deterministic tests (defaults to fresh randomness). */
  nonce?: string;
  /** Forwarded to `listener.awaitCallback` (window / poll / clock overrides). */
  await?: AwaitOptions;
}

/**
 * Build the `oob` {@link Executor} bound to a live interactsh {@link OobListener}.
 * When the listener is absent / not ready (OOB disabled, sidecar down), every PoC
 * is `not_replayable` — a stock scan is unchanged. 008 injects the result into
 * `DEFAULT_EXECUTORS.oob` without touching the runner.
 */
export function createOobExecutor(listener: OobListener | undefined, opts: OobExecutorOptions = {}): Executor {
  return async (poc: Poc, ctx: ExecCtx): Promise<ExecOutcome> => {
    if (!listener?.ready) return inconclusive('interactsh listener not available');
    const base = listener.baseDomain();
    if (!base) return inconclusive('no interactsh base domain');

    const req = poc.request;
    if (!req || typeof req.url !== 'string' || req.url === '') {
      return inconclusive('oob PoC has no request.url');
    }
    if (!hasPlaceholder(req)) {
      return inconclusive(`oob PoC has no ${OOB_CALLBACK_PLACEHOLDER} placeholder`);
    }

    const token = mintToken(base, witnessSeedFor(poc, req), opts.nonce);
    const fired = injectCallback(req, token.callbackHost);

    // SAFETY: the network guard wraps the outbound request, before any fetch.
    try {
      ctx.assertAllowed(fired.url);
    } catch (err) {
      return inconclusive(`network guard blocked: ${err instanceof Error ? err.message : String(err)}`);
    }

    await fireRequest(fired, ctx);

    const hit = await listener.awaitCallback(token, opts.await);
    if (hit) return { observed: true, oobObserved: true };
    // No witnessed callback within the long window — inconclusive, not refuted.
    return inconclusive('no witnessed OOB callback within window');
  };
}

export { matchInteraction, mintToken, parseInteraction, witnessLabel } from './correlate.js';
export type { SpawnFn } from './listener.js';
export { readOobConfig, startInteractshListener } from './listener.js';
export type {
  AwaitOptions,
  OobConfig,
  OobInteraction,
  OobListener,
  OobToken,
} from './types.js';
export { OOB_CALLBACK_PLACEHOLDER } from './types.js';
