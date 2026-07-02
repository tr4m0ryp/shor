// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Canonical RoE hashing — the binding between a launch token and its scope.
 *
 * A launch token is minted bound to `roe_hash` (a hash of the signed Rules of
 * Engagement). At launch, the gate re-hashes the RoE the caller presented and
 * demands an exact match, so a token approved for one scope can never start a run
 * against another. Both sides MUST hash identically, so canonicalization lives
 * here as the single source of truth:
 *
 *   - object keys are emitted in sorted order at every depth,
 *   - arrays keep their given order (order IS semantically meaningful for an
 *     allowlist the operator signed),
 *   - the digest is lowercase hex SHA-256 over the canonical UTF-8 JSON.
 *
 * The operator's approval backend hashes the SAME signed RoE document with the
 * SAME canonicalization to obtain the `roeHash` it passes to `POST /launch-tokens`.
 * Pure + dependency-free beyond node:crypto so it imports safely with no creds.
 */

import { createHash } from 'node:crypto';

/** Recursively emit `value` as JSON with object keys sorted at every depth. */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value ?? null);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    // Drop `undefined`-valued keys so they never affect the digest (JSON would omit them anyway).
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(',')}}`;
}

/**
 * SHA-256 (lowercase hex) of the canonical RoE. Accepts any RoE-shaped object;
 * the caller is responsible for having validated the shape first.
 */
export function hashRoe(roe: unknown): string {
  return createHash('sha256').update(canonicalize(roe), 'utf8').digest('hex');
}
