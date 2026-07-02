// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Launch-token repository — the human-approval gate for MCP-started scans.
 *
 * A token is minted ONLY by the operator's approval path (`POST /launch-tokens`,
 * guarded by a secret the routine never holds) and CONSUMED once by the gated
 * launch (`POST /external/launch`). The consume is a single conditional UPDATE so
 * validation and single-use marking are one atomic step — there is no window in
 * which two concurrent launches could both pass the check and start a scan
 * (no TOCTOU). Not tenant-scoped: a token authorizes an engagement, not a tenant.
 */

import { randomBytes } from 'node:crypto';
import { query } from '../../cloud/pg.js';

export interface LaunchTokenRow {
  id: string;
  token: string;
  engagement_id: string;
  roe_hash: string;
  expires_at: string;
  used_at: string | null;
  created_at: string;
}

/** Input to mint a token: which engagement + RoE hash it authorizes, and its TTL. */
export interface MintLaunchToken {
  readonly engagementId: string;
  readonly roeHash: string;
  readonly ttlSeconds: number;
}

/** A freshly minted token — the opaque value plus its id and expiry (never logged). */
export interface MintedLaunchToken {
  readonly tokenId: string;
  readonly token: string;
  readonly expiresAt: string;
}

/** Criteria the consume must match, all-or-nothing, in one atomic UPDATE. */
export interface ConsumeLaunchToken {
  readonly token: string;
  readonly engagementId: string;
  readonly roeHash: string;
}

export const launchTokenRepo = {
  /**
   * Mint a single-use token bound to `engagementId` + `roeHash`, expiring
   * `ttlSeconds` from now. The token value is 32 random bytes (base64url), opaque
   * and unguessable. Returns the token once; it is never stored or logged in the
   * clear anywhere else.
   */
  async mint(input: MintLaunchToken): Promise<MintedLaunchToken> {
    const token = randomBytes(32).toString('base64url');
    const { rows } = await query<Pick<LaunchTokenRow, 'id' | 'expires_at'>>(
      `INSERT INTO launch_token (token, engagement_id, roe_hash, expires_at)
       VALUES ($1, $2, $3, now() + make_interval(secs => $4))
       RETURNING id, expires_at`,
      [token, input.engagementId, input.roeHash, input.ttlSeconds],
    );
    const row = rows[0] as Pick<LaunchTokenRow, 'id' | 'expires_at'>;
    return { tokenId: row.id, token, expiresAt: row.expires_at };
  },

  /**
   * Atomically validate AND consume a token: it must exist, be unused, be
   * unexpired, and match BOTH the engagement and the RoE hash. On success it is
   * marked used (single-use) in the same statement and its id is returned; any
   * failure returns null and mutates nothing. Returning only the id keeps the
   * secret token out of every downstream log line.
   */
  async consume(input: ConsumeLaunchToken): Promise<{ tokenId: string; engagementId: string } | null> {
    const { rows } = await query<Pick<LaunchTokenRow, 'id' | 'engagement_id'>>(
      `UPDATE launch_token
          SET used_at = now()
        WHERE token = $1
          AND engagement_id = $2
          AND roe_hash = $3
          AND used_at IS NULL
          AND expires_at > now()
        RETURNING id, engagement_id`,
      [input.token, input.engagementId, input.roeHash],
    );
    const row = rows[0];
    return row ? { tokenId: row.id, engagementId: row.engagement_id } : null;
  },
};
