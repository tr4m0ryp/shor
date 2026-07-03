// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Per-account canaries + body-ownership (T7 / F14, R5).
 *
 * A canary is a unique, NON-secret marker seeded into exactly ONE account's object
 * corpus (e.g. a note title / profile bio). It is what turns access-control proof
 * from "silent 200" guessing into a real ownership assertion: if identity B's
 * response to A's resource carries A's canary, B literally saw A's data — the
 * body-ownership signal the four-way matrix decides on, NEVER the status code.
 *
 * A canary token is deliberately a distinct, greppable `shor-cnry-<uuid>` string:
 * unique per account so a leak is attributable, and inert (no privilege) so seeding
 * it is safe. Tokens here are markers, not credentials — they are not secrets and
 * may appear in logs.
 */

import { randomUUID } from 'node:crypto';

/** A minted marker bound to one account. */
export interface AccountCanary {
  /** Non-secret account label this canary belongs to (e.g. 'account-a'). */
  readonly account: string;
  /** Unique marker seeded into this account's object corpus. */
  readonly token: string;
}

/** A concrete seed instruction: the field + value a caller writes into the account. */
export interface CanarySeed {
  readonly account: string;
  /** Object field to write the canary into (a low-risk, readable-back field). */
  readonly field: string;
  /** The value to write — the canary token. */
  readonly value: string;
}

const CANARY_PREFIX = 'shor-cnry';

/** Mint a fresh, unique canary for one account. */
export function mintCanary(account: string): AccountCanary {
  return { account, token: `${CANARY_PREFIX}-${randomUUID()}` };
}

/**
 * Build the seed instruction a caller (008) writes into the account's object corpus
 * before the matrix runs. Kept declarative so the actual write goes through the
 * flag-gated, RoE-checked executor — not this pure module.
 */
export function canarySeed(canary: AccountCanary, field = 'note'): CanarySeed {
  return { account: canary.account, field, value: canary.token };
}

/** Does a response body carry THIS account's canary? (the body-ownership check). */
export function bodyCarriesCanary(body: string | undefined, canary: AccountCanary): boolean {
  return typeof body === 'string' && body.includes(canary.token);
}

/**
 * Which account's canary (if any) a body carries — first match wins. Lets a caller
 * distinguish "B saw A's data" (victim canary) from "B saw its OWN data" (peer
 * canary) — the distinct-marker guard that kills the "every id gets a 200" FP.
 */
export function bodyOwner(
  body: string | undefined,
  canaries: readonly AccountCanary[],
): AccountCanary | undefined {
  if (typeof body !== 'string') return undefined;
  for (const c of canaries) {
    if (body.includes(c.token)) return c;
  }
  return undefined;
}
