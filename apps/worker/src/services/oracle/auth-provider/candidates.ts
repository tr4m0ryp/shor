// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Shared candidate helpers: durability ranks, header builders, ordering, and the
 * Playwright storage-state reader every cookie/bearer provider draws from. Kept
 * generic — no WordPress specifics live here (those stay in `wordpress.ts`).
 */

import fs from 'node:fs';
import path from 'node:path';
import type { AuthCandidate, AuthCandidateKind } from './types.js';

/** The privileged baseline session dir — its cookies are already in the PoC. */
export const PRIMARY_SESSION_DIR = 'identity-primary';

/**
 * Durability ranks — HIGHER survives session churn better, so a provider tries it
 * first and `reauth` falls to the next. App-passwords / basic outrank a nonce'd
 * cookie, which outranks a bare cookie (the flakiest, first to be logged out).
 */
export const DURABILITY: Readonly<Record<AuthCandidateKind, number>> = {
  'app-password': 100,
  basic: 90,
  'api-key': 80,
  bearer: 60,
  'oidc-bearer': 55,
  'cookie+csrf': 40,
  cookie: 20,
};

/** Order candidates most-durable-first; stable within equal ranks. */
export function orderCandidates(cands: readonly AuthCandidate[]): AuthCandidate[] {
  return [...cands].sort((a, b) => b.durability - a.durability);
}

/** The next (less-durable) candidate after `spent`, or `undefined` when exhausted. */
export function nextCandidate(
  ordered: readonly AuthCandidate[],
  spent: AuthCandidate,
): AuthCandidate | undefined {
  const idx = ordered.indexOf(spent);
  if (idx < 0) return ordered[0];
  return ordered[idx + 1];
}

export function cookieCandidate(cookieHeader: string): AuthCandidate {
  return { kind: 'cookie', durability: DURABILITY.cookie, headers: { Cookie: cookieHeader } };
}

/** Cookie plus a CSRF/nonce header (a session that carries an anti-CSRF token). */
export function cookieCsrfCandidate(cookieHeader: string, csrfHeader: string, csrf: string): AuthCandidate {
  return {
    kind: 'cookie+csrf',
    durability: DURABILITY['cookie+csrf'],
    headers: { Cookie: cookieHeader, [csrfHeader]: csrf },
  };
}

export function bearerCandidate(token: string): AuthCandidate {
  return { kind: 'bearer', durability: DURABILITY.bearer, headers: { Authorization: `Bearer ${token}` } };
}

export function oidcBearerCandidate(token: string): AuthCandidate {
  return { kind: 'oidc-bearer', durability: DURABILITY['oidc-bearer'], headers: { Authorization: `Bearer ${token}` } };
}

export function apiKeyCandidate(headerName: string, key: string): AuthCandidate {
  return { kind: 'api-key', durability: DURABILITY['api-key'], headers: { [headerName]: key } };
}

/** HTTP Basic (username:secret already base64-encoded by the caller). */
export function basicCandidate(base64: string, kind: 'basic' | 'app-password' = 'basic'): AuthCandidate {
  return { kind, durability: DURABILITY[kind], headers: { Authorization: `Basic ${base64}` } };
}

/** Extract the bearer token from an Authorization header, if present. */
export function bearerTokenOf(headers: Readonly<Record<string, string>>): string | undefined {
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === 'authorization') {
      const m = /^Bearer\s+(.+)$/i.exec(v.trim());
      if (m?.[1]) return m[1];
    }
  }
  return undefined;
}

interface RawCookie {
  name?: unknown;
  value?: unknown;
}
interface RawLocalItem {
  name?: unknown;
  value?: unknown;
}
interface RawOrigin {
  origin?: unknown;
  localStorage?: unknown;
}

/** Parsed, validated Playwright storage-state (cookies + localStorage per origin). */
export interface StorageState {
  cookies: { name: string; value: string }[];
  origins: { origin: string; localStorage: { name: string; value: string }[] }[];
}

function pairs(items: unknown): { name: string; value: string }[] {
  if (!Array.isArray(items)) return [];
  const out: { name: string; value: string }[] = [];
  for (const raw of items as (RawCookie | RawLocalItem)[]) {
    if (typeof raw?.name === 'string' && typeof raw?.value === 'string') out.push({ name: raw.name, value: raw.value });
  }
  return out;
}

/** Read + validate a Playwright storage-state file; `undefined` on any failure. */
export function readStorageState(statePath: string): StorageState | undefined {
  try {
    const doc = JSON.parse(fs.readFileSync(statePath, 'utf8')) as { cookies?: unknown; origins?: unknown };
    const origins = Array.isArray(doc.origins) ? (doc.origins as RawOrigin[]) : [];
    return {
      cookies: pairs(doc.cookies),
      origins: origins
        .filter((o): o is RawOrigin & { origin: string } => typeof o?.origin === 'string')
        .map((o) => ({ origin: o.origin, localStorage: pairs(o.localStorage) })),
    };
  } catch {
    return undefined;
  }
}

/** Build a `Cookie:` header value from a parsed storage-state; '' when empty. */
export function cookieHeaderFrom(state: StorageState): string {
  return state.cookies.map((c) => `${c.name}=${c.value}`).join('; ');
}

/** Candidate locations of the per-identity session dirs, relative to deliverables. */
function identityDirCandidates(deliverablesPath: string): string[] {
  return [
    path.join(path.dirname(deliverablesPath), '.playwright-cli', 'identities'),
    path.join(deliverablesPath, '.playwright-cli', 'identities'),
  ];
}

/** One discovered, non-primary identity: its dir label + parsed storage-state. */
export interface IdentityState {
  label: string;
  state: StorageState;
}

/**
 * Discover every NON-primary identity session dir that has readable storage-state.
 * Directory-driven (no manifest/slug coupling); the primary dir is excluded as the
 * privileged baseline. Mirrors the legacy loader: try each candidate root and stop
 * at the first that yields any identity. Fail-open — an unreadable root is skipped.
 */
export function discoverIdentityStates(deliverablesPath: string): IdentityState[] {
  const out: IdentityState[] = [];
  for (const root of identityDirCandidates(deliverablesPath)) {
    let dirs: string[];
    try {
      dirs = fs.readdirSync(root);
    } catch {
      continue;
    }
    for (const dir of dirs) {
      if (dir === PRIMARY_SESSION_DIR) continue;
      const state = readStorageState(path.join(root, dir, 'storage-state.json'));
      if (state) out.push({ label: dir, state });
    }
    if (out.length > 0) break;
  }
  return out;
}
