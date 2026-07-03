// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Pure correlation logic for the OOB proof path (spec T8, F14, R6).
 *
 * Mint a per-payload token (fresh nonce + request-bound witness), parse an
 * interactsh JSONL interaction into a set of whole DNS labels, and decide —
 * BOUNDARY-SAFE — whether a callback proves the fired request. No I/O here; the
 * sidecar/poll loop lives in `listener.ts`. Everything is deterministic given an
 * injected nonce, so the matcher is exhaustively unit-testable over fixtures.
 */

import { createHash, randomBytes } from 'node:crypto';
import type { OobInteraction, OobToken } from './types.js';

/** Witness length: 12 hex chars = 48 bits, a stable request-bound label. */
const WITNESS_HEX_CHARS = 12;
/** Nonce length: 16 hex chars = 64 bits of freshness per attempt. */
const NONCE_HEX_CHARS = 16;

/** A single DNS label: letters/digits/hyphen only (already lowercased by callers). */
const LABEL_RE = /^[a-z0-9-]+$/;
/** An FQDN-ish run inside a raw request dump (question name, Host header, …). */
const FQDN_RE = /[a-z0-9-]+(?:\.[a-z0-9-]+)+/gi;

/** Split a host into its whole, lowercased DNS labels (boundary-safe unit). */
function hostLabels(host: string): string[] {
  return host
    .toLowerCase()
    .split('.')
    .filter((label) => LABEL_RE.test(label));
}

/**
 * The request-bound witness: a short hex label derived from the material that
 * uniquely identifies THIS fired payload (finding id + method + url + body). A
 * foreign callback cannot carry it, so it rejects third-party-scanner hits.
 */
export function witnessLabel(seed: string): string {
  return createHash('sha256').update(seed).digest('hex').slice(0, WITNESS_HEX_CHARS);
}

/**
 * Mint a fresh, witnessed callback token under an interactsh base domain.
 * `callbackHost = <nonce>.<witness>.<baseDomain>` — DNS-first: even when the
 * target's HTTP egress is filtered, its DNS resolution of the host still reaches
 * the interactsh server. `nonce` is injectable so tests are deterministic.
 */
export function mintToken(baseDomain: string, witnessSeed: string, nonce?: string): OobToken {
  const base = baseDomain
    .trim()
    .toLowerCase()
    .replace(/^\.+|\.+$/g, '');
  const correlationLabel = base.split('.')[0] ?? '';
  const freshNonce = (nonce ?? randomBytes(8).toString('hex')).toLowerCase();
  const witness = witnessLabel(witnessSeed);
  return {
    nonce: freshNonce.slice(0, NONCE_HEX_CHARS),
    witness,
    correlationLabel,
    callbackHost: `${freshNonce.slice(0, NONCE_HEX_CHARS)}.${witness}.${base}`,
    baseDomain: base,
  };
}

function asString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

/**
 * Parse one interactsh JSONL line into an {@link OobInteraction}. Tolerant of the
 * field-name drift across interactsh versions (`unique-id`/`uniqueId`,
 * `full-id`/`fullId`, `raw-request`/`rawRequest`). Returns undefined for a blank
 * or non-object line. The label set is the union of every whole DNS label seen in
 * `full-id` and any FQDN inside the raw request dump.
 */
export function parseInteraction(line: string): OobInteraction | undefined {
  const trimmed = line.trim();
  if (trimmed === '' || trimmed[0] !== '{') return undefined;
  let raw: unknown;
  try {
    raw = JSON.parse(trimmed);
  } catch {
    return undefined;
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const r = raw as Record<string, unknown>;

  const protocol = asString(r.protocol).toLowerCase();
  const correlationId = asString(r['unique-id'] ?? r.uniqueId).toLowerCase();
  const fullId = asString(r['full-id'] ?? r.fullId);
  const rawRequest = asString(r['raw-request'] ?? r.rawRequest);
  // Only accept a line that is actually an interaction, not some other JSON.
  if (protocol === '' && correlationId === '' && fullId === '') return undefined;

  const labels = new Set<string>();
  for (const label of hostLabels(fullId)) labels.add(label);
  for (const fqdn of rawRequest.toLowerCase().match(FQDN_RE) ?? []) {
    for (const label of hostLabels(fqdn)) labels.add(label);
  }

  return {
    protocol,
    correlationId,
    labels,
    remoteAddress: asString(r['remote-address'] ?? r.remoteAddress),
    timestamp: asString(r.timestamp),
  };
}

/**
 * Boundary-safe, witnessed correlation. A callback proves the fired request ONLY
 * when the interaction carries, as WHOLE DNS labels, our fresh `nonce`, the
 * request-bound `witness`, AND our session `correlationLabel`. Whole-label set
 * membership (never substring) rules out a false positive where a token merely
 * appears inside a longer label. When the server reported a `unique-id`, it must
 * be a prefix of our correlation label (defense in depth) — an empty one is not a
 * rejection, since some protocols omit it.
 */
export function matchInteraction(token: OobToken, interaction: OobInteraction): boolean {
  if (!interaction.labels.has(token.nonce)) return false;
  if (!interaction.labels.has(token.witness)) return false;
  if (token.correlationLabel !== '' && !interaction.labels.has(token.correlationLabel)) return false;
  if (interaction.correlationId !== '' && !token.correlationLabel.startsWith(interaction.correlationId)) {
    return false;
  }
  return true;
}
