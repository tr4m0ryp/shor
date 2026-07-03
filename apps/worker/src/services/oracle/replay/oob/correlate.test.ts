// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Pure-logic tests for OOB correlation: token minting, JSONL interaction parsing,
 * and the boundary-safe witnessed matcher. Covers the task's required matrix —
 * matching-witness callback ⇒ confirmed; no-witness / foreign hit ⇒ rejected;
 * boundary-safe label match (no substring false-positive).
 */

import { describe, expect, it } from 'vitest';
import { matchInteraction, mintToken, parseInteraction, witnessLabel } from './correlate.js';

// A realistic interactsh base: 20-char correlation id + 13-char random = 33-char label.
const CORR = 'abcdefghij0123456789';
const RAND = 'klmnopqrstuvw';
const BASE_LABEL = CORR + RAND;
const BASE = `${BASE_LABEL}.oast.example.net`;
const NONCE = 'deadbeefdeadbeef';
const SEED = 'AUTH-VULN-01\nGET https://t.example/x?u={{OOB_CALLBACK}}\n';

const token = mintToken(BASE, SEED, NONCE);

/** Build one interactsh JSONL line for a given queried subdomain. */
function dnsLine(sub: string, over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    protocol: 'dns',
    'unique-id': CORR,
    'full-id': sub,
    'q-type': 'A',
    'raw-request': `;; QUESTION SECTION:\n;${sub}.oast.example.net. IN A`,
    'remote-address': '203.0.113.9',
    timestamp: '2026-07-03T00:00:00Z',
    ...over,
  });
}

describe('mintToken', () => {
  it('derives a fresh, request-bound, DNS-first callback host', () => {
    expect(token.nonce).toBe(NONCE);
    expect(token.witness).toBe(witnessLabel(SEED));
    expect(token.correlationLabel).toBe(BASE_LABEL);
    expect(token.callbackHost).toBe(`${NONCE}.${token.witness}.${BASE}`);
  });

  it('binds the witness to the seed — a different payload yields a different witness', () => {
    const other = mintToken(BASE, `${SEED}other`, NONCE);
    expect(other.witness).not.toBe(token.witness);
    expect(other.callbackHost).not.toBe(token.callbackHost);
  });

  it('uses fresh randomness per attempt when no nonce is injected', () => {
    const a = mintToken(BASE, SEED);
    const b = mintToken(BASE, SEED);
    expect(a.nonce).not.toBe(b.nonce);
  });
});

describe('parseInteraction', () => {
  it('parses a DNS interaction into a whole-label set', () => {
    const parsed = parseInteraction(dnsLine(`${NONCE}.${token.witness}.${BASE_LABEL}`));
    expect(parsed?.protocol).toBe('dns');
    expect(parsed?.correlationId).toBe(CORR);
    expect(parsed?.labels.has(NONCE)).toBe(true);
    expect(parsed?.labels.has(token.witness)).toBe(true);
    expect(parsed?.labels.has(BASE_LABEL)).toBe(true);
  });

  it('tolerates camelCase field drift across interactsh versions', () => {
    const line = JSON.stringify({
      protocol: 'http',
      uniqueId: CORR,
      fullId: `${NONCE}.${token.witness}.${BASE_LABEL}`,
      rawRequest: `GET / HTTP/1.1\nHost: ${NONCE}.${token.witness}.${BASE}`,
    });
    const parsed = parseInteraction(line);
    expect(parsed?.correlationId).toBe(CORR);
    expect(parsed?.labels.has(token.witness)).toBe(true);
  });

  it('rejects blank, banner, and non-interaction lines', () => {
    expect(parseInteraction('')).toBeUndefined();
    expect(parseInteraction('[INF] Listing 1 payload for OOB Testing')).toBeUndefined();
    expect(parseInteraction(`${BASE}`)).toBeUndefined();
    expect(parseInteraction(JSON.stringify({ note: 'not an interaction' }))).toBeUndefined();
    expect(parseInteraction('{not json')).toBeUndefined();
  });
});

describe('matchInteraction (witnessed, boundary-safe)', () => {
  it('CONFIRMS a callback carrying nonce + witness + correlation', () => {
    const hit = parseInteraction(dnsLine(`${NONCE}.${token.witness}.${BASE_LABEL}`));
    expect(hit && matchInteraction(token, hit)).toBe(true);
  });

  it('REJECTS a callback with the correct correlation but NO witness (preview-bot / base-URL hit)', () => {
    // A bot that expands only the raw base interactsh URL: correlation present, no sub-labels.
    const hit = parseInteraction(dnsLine(BASE_LABEL));
    expect(hit && matchInteraction(token, hit)).toBe(false);
  });

  it('REJECTS a callback with nonce + correlation but the WRONG witness', () => {
    const wrong = witnessLabel('some-other-payload');
    const hit = parseInteraction(dnsLine(`${NONCE}.${wrong}.${BASE_LABEL}`));
    expect(hit && matchInteraction(token, hit)).toBe(false);
  });

  it('REJECTS a foreign third-party-scanner hit on the same server', () => {
    const foreign = parseInteraction(
      dnsLine('zzscannerzz9988776655.oast.example.net', { 'unique-id': 'zzscannerzz998877665' }),
    );
    expect(foreign && matchInteraction(token, foreign)).toBe(false);
  });

  it('is BOUNDARY-SAFE: nonce as a substring of a longer label does not match', () => {
    // `xdeadbeefdeadbeef` contains the nonce but is a different whole label.
    const hit = parseInteraction(dnsLine(`x${NONCE}.${token.witness}.${BASE_LABEL}`));
    expect(hit?.labels.has(NONCE)).toBe(false);
    expect(hit && matchInteraction(token, hit)).toBe(false);
  });

  it('is BOUNDARY-SAFE: witness as a substring of a longer label does not match', () => {
    const hit = parseInteraction(dnsLine(`${NONCE}.${token.witness}zz.${BASE_LABEL}`));
    expect(hit && matchInteraction(token, hit)).toBe(false);
  });

  it('REJECTS when the reported unique-id is not a prefix of our correlation label', () => {
    const hit = parseInteraction(
      dnsLine(`${NONCE}.${token.witness}.${BASE_LABEL}`, { 'unique-id': 'ffffffffffffffffffff' }),
    );
    expect(hit && matchInteraction(token, hit)).toBe(false);
  });
});
