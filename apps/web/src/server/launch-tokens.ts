// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * `POST /launch-tokens` — the operator-only mint for human-approval launch tokens.
 *
 * This is the trust boundary. It is authed by `SHOR_LAUNCH_MINT_TOKEN`, a secret
 * held ONLY by the operator's approval backend (the Telegram Approve button) —
 * DELIBERATELY not the `engineTriggerToken` the MCP connector holds. So the MCP
 * (and any routine behind it) can CONSUME a token at `/external/launch` but has no
 * way to MINT one here: the human who clicks Approve is structurally in the loop.
 *
 * Body: `{ engagementId, roeHash, ttlSeconds }`. Mints a single-use token bound to
 * that engagement + RoE hash and returns `{ tokenId, token, expiresAt }`. The
 * bearer is constant-time compared and never logged; an empty configured secret
 * disables minting entirely (every request 401s).
 */

import { getConfig } from '../config.js';
import { launchTokenRepo } from '../db/repositories/index.js';
import type { ApiResponse } from './router.js';

const UNAUTHORIZED: ApiResponse = { status: 401, body: { error: 'unauthorized' } };
const METHOD_NOT_ALLOWED: ApiResponse = { status: 405, body: { error: 'Method not allowed' } };

/** Max TTL a minted token may carry (24h) — a bounded approval, never open-ended. */
const MAX_TTL_SECONDS = 24 * 60 * 60;
const DEFAULT_TTL_SECONDS = 15 * 60;

function bearerToken(authHeader: string | undefined): string | undefined {
  if (!authHeader) return undefined;
  const m = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
  return m ? m[1] : undefined;
}

/** Length-independent constant-time equality (never short-circuits, never logs). */
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Authorize against the operator-only mint secret. Empty secret ⇒ disabled. */
function authorizeMint(authHeader: string | undefined): boolean {
  const { launchMintToken } = getConfig().sinas;
  if (launchMintToken === '') return false;
  const presented = bearerToken(authHeader);
  return presented !== undefined && safeEqual(presented, launchMintToken);
}

export async function routeLaunchTokens(
  method: string,
  body: Record<string, unknown>,
  authHeader: string | undefined,
): Promise<ApiResponse> {
  if (method !== 'POST') return METHOD_NOT_ALLOWED;
  if (!authorizeMint(authHeader)) return UNAUTHORIZED;

  const engagementId = typeof body.engagementId === 'string' ? body.engagementId.trim() : '';
  const roeHash = typeof body.roeHash === 'string' ? body.roeHash.trim().toLowerCase() : '';
  if (!engagementId) return { status: 400, body: { error: 'engagementId is required' } };
  if (!/^[0-9a-f]{64}$/.test(roeHash)) return { status: 400, body: { error: 'roeHash must be a sha256 hex digest' } };

  const rawTtl = typeof body.ttlSeconds === 'number' ? Math.floor(body.ttlSeconds) : DEFAULT_TTL_SECONDS;
  const ttlSeconds = Math.min(Math.max(rawTtl, 1), MAX_TTL_SECONDS);

  try {
    const minted = await launchTokenRepo.mint({ engagementId, roeHash, ttlSeconds });
    return { status: 201, body: { tokenId: minted.tokenId, token: minted.token, expiresAt: minted.expiresAt } };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { status: 500, body: { error: msg } };
  }
}
