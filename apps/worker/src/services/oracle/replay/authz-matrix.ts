// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Four-way differential authz matrix (T7 / F4 / F14, R5).
 *
 * Access-control bypasses are "silent" 200s — a status code proves nothing (a
 * god-mode account 200s on everything; a public resource 200s for everyone). This
 * decides a bypass on BODY-OWNERSHIP against planted per-account canaries across a
 * four-way differential, never on status:
 *
 *   - A→A (positive control)  — A reading A's own resource; establishes what a
 *                               legitimate success looks like and that A's canary is
 *                               visible. Repeated for the SELF-NOISE floor.
 *   - self-noise floor        — variance across the repeated A→A reads (after volatile
 *                               fields are normalized) sets the similarity band two
 *                               responses must fall within to count as "the same".
 *   - B→A (bypass test)       — a SYMMETRIC low-priv peer B reading A's resource. B
 *                               carrying A's canary within the noise band is the leak.
 *   - Anon→A (public baseline)— disambiguates "cross-user bypass" from "public
 *                               resource" (anon also gets it) from "no-auth-at-all".
 *
 * Verdict is 3-valued: `bypassed` ONLY when B→A ≈ A→A within the self-noise band AND
 * B's body carries A's canary AND Anon→A was denied; `enforced` otherwise (including
 * "public"); `unknown` when the positive control or the peer leg could not be run.
 * Fail-open: uncertainty is `unknown`, never a refutation.
 *
 * Symmetric low-priv peers (never a god-mode account) are the #1 FP killer —
 * {@link selectSymmetricPeers} picks them from the provider identities (task 004).
 * This module is PURE decision logic; task 008 wires it into the oracle.
 */

import type { ProviderIdentity } from '../auth-provider/index.js';
import { bodyCarriesCanary, type AccountCanary } from './canary.js';
import type { ExecOutcome } from './types.js';

/** 3-valued matrix verdict. */
export type AuthzVerdict = 'bypassed' | 'enforced' | 'unknown';

/** Non-secret detail of why the matrix landed on its verdict. */
export type AuthzReason =
  | 'cross_user_bypass'
  | 'access_control_enforced'
  | 'public_resource'
  | 'positive_control_failed'
  | 'peer_not_attempted';

/** The four legs + the canaries the decision keys on. */
export interface AuthzMatrixInput {
  /** A→A positive-control samples; ≥ 2 give a real self-noise band. */
  readonly selfToSelf: readonly ExecOutcome[];
  /** B→A — B is a SYMMETRIC low-priv peer, never a god-mode account. */
  readonly peerToTarget: ExecOutcome;
  /** Anon→A public baseline. */
  readonly anonToTarget: ExecOutcome;
  /** A's planted canary (body-ownership keys on this). */
  readonly targetCanary: AccountCanary;
  /** B's OWN canary — proves B saw its own data, not A's (distinct-marker guard). */
  readonly peerCanary?: AccountCanary;
}

/** Orthogonal audit axes behind the verdict (non-secret). */
export interface AuthzFactors {
  readonly positiveControl: boolean;
  readonly selfNoiseBand: number;
  readonly peerObserved: boolean;
  readonly anonObserved: boolean;
  readonly peerCarriesTargetCanary: boolean;
  readonly peerCarriesOwnCanary: boolean;
  readonly peerSelfSimilarity: number;
  readonly peerWithinBand: boolean;
  readonly anonReproduced: boolean;
}

export interface AuthzDecision {
  readonly verdict: AuthzVerdict;
  readonly reason: AuthzReason;
  readonly factors: AuthzFactors;
}

/** Tunables for {@link decideAuthz}. */
export interface AuthzOptions {
  /** Self-noise band used when there are < 2 A→A samples. */
  readonly defaultBand?: number;
  /** Slack subtracted from the band when testing the peer/anon (tolerance). */
  readonly bandSlack?: number;
}

const DEFAULT_BAND = 0.9;
const DEFAULT_SLACK = 0.05;

/**
 * Volatile response fragments that legitimately differ between two identical reads —
 * normalized away before similarity so they do not depress the self-noise band. NOT
 * applied to the canary check (that keys on the raw body).
 */
const VOLATILE_PATTERNS: readonly RegExp[] = [
  /\b\d{4}-\d{2}-\d{2}t[\d:.]+z?\b/gi, // ISO-8601 timestamps
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, // UUIDs
  /\b[0-9a-f]{32,}\b/gi, // long hex (csrf / session / etag)
  /"(?:csrf|nonce|_token|token|requestid|request_id|timestamp|etag)"\s*:\s*"[^"]*"/gi,
  /\b\d{10,}\b/g, // epoch-ish long integers
];

function stripVolatile(body: string): string {
  let out = body;
  for (const re of VOLATILE_PATTERNS) out = out.replace(re, ' ');
  return out;
}

/** Content word-set of a body, volatile fields stripped and lowercased. */
function tokenize(body: string | undefined): Set<string> {
  if (typeof body !== 'string' || body === '') return new Set();
  const cleaned = stripVolatile(body).toLowerCase();
  return new Set(cleaned.split(/[^a-z0-9_]+/).filter((w) => w.length >= 2));
}

/**
 * Jaccard similarity of two bodies over their normalized content word-sets, in
 * [0,1]. Two empty bodies are identical (1); one empty vs non-empty is disjoint (0).
 */
export function bodySimilarity(a: string | undefined, b: string | undefined): number {
  const sa = tokenize(a);
  const sb = tokenize(b);
  if (sa.size === 0 && sb.size === 0) return 1;
  if (sa.size === 0 || sb.size === 0) return 0;
  let inter = 0;
  for (const t of sa) {
    if (sb.has(t)) inter += 1;
  }
  const union = sa.size + sb.size - inter;
  return union === 0 ? 1 : inter / union;
}

/** Bodies of the observed A→A samples, in order. */
function observedSelfBodies(samples: readonly ExecOutcome[]): string[] {
  const out: string[] = [];
  for (const s of samples) {
    if (s.observed) out.push(s.body ?? '');
  }
  return out;
}

/** Minimum pairwise similarity across the A→A samples — the self-noise floor. */
function selfNoiseBand(samples: readonly ExecOutcome[], fallback: number): number {
  const bodies = observedSelfBodies(samples);
  if (bodies.length < 2) return fallback;
  let min = 1;
  for (let i = 0; i < bodies.length; i += 1) {
    for (let j = i + 1; j < bodies.length; j += 1) {
      const sim = bodySimilarity(bodies[i], bodies[j]);
      if (sim < min) min = sim;
    }
  }
  return min;
}

/**
 * A representative A→A body: the first observed sample that carries A's canary (a
 * proven-legitimate view), else the first observed sample. `undefined` when A never
 * responded (positive control failed).
 */
function representativeSelf(samples: readonly ExecOutcome[], canary: AccountCanary): string | undefined {
  let anyBody: string | undefined;
  let sawObserved = false;
  for (const s of samples) {
    if (!s.observed) continue;
    if (!sawObserved) {
      anyBody = s.body;
      sawObserved = true;
    }
    if (bodyCarriesCanary(s.body, canary)) return s.body;
  }
  return anyBody;
}

/** Did A demonstrably read A's OWN resource (a sample carrying A's canary)? */
function positiveControlOk(samples: readonly ExecOutcome[], canary: AccountCanary): boolean {
  return samples.some((s) => s.observed && bodyCarriesCanary(s.body, canary));
}

/**
 * Decide the four-way matrix. Pure; never fires a request. The bypass gate is
 * fail-CLOSED (all of: peer body-ownership, within the self-noise band, anon denied);
 * every uncertainty fails OPEN to `unknown`.
 */
export function decideAuthz(input: AuthzMatrixInput, options: AuthzOptions = {}): AuthzDecision {
  const slack = options.bandSlack ?? DEFAULT_SLACK;
  const band = selfNoiseBand(input.selfToSelf, options.defaultBand ?? DEFAULT_BAND);
  const positiveControl = positiveControlOk(input.selfToSelf, input.targetCanary);
  const selfBody = representativeSelf(input.selfToSelf, input.targetCanary);

  const anon = input.anonToTarget;
  const anonObserved = anon.observed;
  const anonReproduced =
    anon.observed &&
    (bodyCarriesCanary(anon.body, input.targetCanary) ||
      bodySimilarity(anon.body, selfBody) >= band - slack);

  const peer = input.peerToTarget;
  const peerObserved = peer.observed;
  const peerCarriesTargetCanary = peer.observed && bodyCarriesCanary(peer.body, input.targetCanary);
  const peerCarriesOwnCanary =
    peer.observed && input.peerCanary !== undefined && bodyCarriesCanary(peer.body, input.peerCanary);
  const peerSelfSimilarity = peer.observed ? bodySimilarity(peer.body, selfBody) : 0;
  const peerWithinBand = peerSelfSimilarity >= band - slack;

  const factors: AuthzFactors = {
    positiveControl,
    selfNoiseBand: band,
    peerObserved,
    anonObserved,
    peerCarriesTargetCanary,
    peerCarriesOwnCanary,
    peerSelfSimilarity,
    peerWithinBand,
    anonReproduced,
  };

  // 1. Without a working positive control we cannot interpret anything — unknown.
  if (!positiveControl) return { verdict: 'unknown', reason: 'positive_control_failed', factors };
  // 2. Anon also gets A's resource ⇒ it is public, not a cross-user bypass ⇒ dismiss.
  if (anonReproduced) return { verdict: 'enforced', reason: 'public_resource', factors };
  // 3. The peer leg could not be run ⇒ we never tested the boundary ⇒ unknown.
  if (!peerObserved) return { verdict: 'unknown', reason: 'peer_not_attempted', factors };
  // 4. Fail-closed bypass: B holds A's canary AND its view matches A's within the band.
  if (peerCarriesTargetCanary && peerWithinBand) {
    return { verdict: 'bypassed', reason: 'cross_user_bypass', factors };
  }
  // 5. The boundary held (B saw its own data / no canary / a different view).
  return { verdict: 'enforced', reason: 'access_control_enforced', factors };
}

/**
 * Role/label tokens that mark a privileged (god-mode) account to EXCLUDE as a peer —
 * feeding one is the classic authz false positive (it is SUPPOSED to see A's data).
 */
const GOD_MODE_TOKENS: readonly string[] = [
  'admin',
  'administrator',
  'superuser',
  'superadmin',
  'super-admin',
  'root',
  'owner',
  'sysadmin',
  'operator',
  'staff',
  'god',
];

function isGodMode(identity: ProviderIdentity): boolean {
  const hay = `${identity.label} ${identity.principal.role ?? ''}`.toLowerCase();
  return GOD_MODE_TOKENS.some((t) => hay.includes(t));
}

/**
 * Pick two SYMMETRIC low-priv peers (A, B) from the provider identities (task 004).
 * Symmetric = same role token (or both role-less); god-mode-looking identities are
 * excluded first. `undefined` when no symmetric pair exists — the caller then leaves
 * the B→A leg unattempted (matrix → `unknown`), never substituting a god-mode account.
 */
export function selectSymmetricPeers(
  identities: readonly ProviderIdentity[],
): { a: ProviderIdentity; b: ProviderIdentity } | undefined {
  const peers = identities.filter((i) => !isGodMode(i));
  const byRole = new Map<string, ProviderIdentity[]>();
  for (const p of peers) {
    const key = (p.principal.role ?? '').trim().toLowerCase();
    const bucket = byRole.get(key) ?? [];
    bucket.push(p);
    byRole.set(key, bucket);
  }
  for (const bucket of byRole.values()) {
    if (bucket.length >= 2) {
      const [a, b] = bucket;
      if (a && b) return { a, b };
    }
  }
  return undefined;
}
