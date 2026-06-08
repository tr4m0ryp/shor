// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Per-finding, mechanism-aware CWE mapper (T4).
 *
 * The old path used a single `meta.defaultCwe` per category, which produced a
 * 16×CWE-287 / 14×CWE-862 monoculture (scan 0007). This module keys the CWE off
 * the finding's actual mechanism (`vulnerability_type` + descriptive tokens) so a
 * hardcoded key reads CWE-798, an open redirect CWE-601, SSRF CWE-918, etc.
 *
 * Resolution order (in `toFindingRecord`):
 *   explicit raw CWE  →  mechanism map (here)  →  category default.
 * `cwe_inferred` is set TRUE only when resolution falls through to the category
 * default — i.e. neither an explicit CWE nor a mechanism match was found. That
 * lets the finalize layer flag CWEs it had to guess.
 */

import { explicitCwe } from '../category-meta.js';
import type { FindingCategory } from '../types.js';

/** Result of CWE resolution: the chosen CWE + whether it is a category-default guess. */
export interface CweResolution {
  cwe: string;
  /** True ONLY when the CWE fell through to the category default (no specific match). */
  inferred: boolean;
}

/**
 * Raw fields that may describe the mechanism. `vulnerability_type` is primary;
 * the rest are scanned so a token like "open redirect" or "hardcoded secret"
 * appearing in the type/notes/defense still maps. Kept narrow + deterministic.
 */
const MECHANISM_TEXT_KEYS = [
  'vulnerability_type',
  'weakness_type',
  'type',
  'notes',
  'mismatch_reason',
  'missing_defense',
  'broken_invariant',
  'misconfiguration_detail',
  'reason',
];

/**
 * A mechanism rule: when `match(tokens)` holds for the combined mechanism text,
 * map to `cwe`. Order matters — the FIRST matching rule wins, so more specific
 * rules precede broader ones.
 */
interface MechanismRule {
  cwe: string;
  match: (text: string) => boolean;
}

const has = (text: string, ...needles: string[]): boolean => needles.some((n) => text.includes(n));

/**
 * Mechanism → CWE rules, most specific first. `text` is the lowercased,
 * whitespace-normalized concatenation of the mechanism fields (see
 * {@link MECHANISM_TEXT_KEYS}).
 */
const MECHANISM_RULES: readonly MechanismRule[] = [
  // Hardcoded / embedded credentials, keys, secrets → CWE-798.
  {
    cwe: 'CWE-798',
    match: (t) =>
      has(t, 'hardcoded', 'hard coded', 'hard-coded', 'embedded credential') &&
      has(t, 'credential', 'secret', 'key', 'password', 'token', 'api key', 'apikey'),
  },
  // Open redirect / unvalidated forward → CWE-601.
  {
    cwe: 'CWE-601',
    match: (t) =>
      has(t, 'open redirect', 'open_redirect', 'unvalidated redirect') ||
      (has(t, 'redirect') && has(t, 'unvalidated', 'open', 'external', 'arbitrary')),
  },
  // SSRF → CWE-918.
  {
    cwe: 'CWE-918',
    match: (t) => has(t, 'ssrf', 'server-side request forgery', 'server side request forgery'),
  },
  // Path / directory traversal → CWE-22.
  {
    cwe: 'CWE-22',
    match: (t) => has(t, 'path traversal', 'directory traversal', '../', 'lfi', 'local file inclusion'),
  },
  // SQL injection → CWE-89.
  {
    cwe: 'CWE-89',
    match: (t) => has(t, 'sql injection', 'sqli', 'sql-injection'),
  },
  // OS command injection → CWE-78.
  {
    cwe: 'CWE-78',
    match: (t) => has(t, 'command injection', 'os command', 'rce', 'remote code execution', 'shell injection'),
  },
  // JWT algorithm confusion — ONLY when asymmetric (RS/ES/PS → HS) is named.
  // `alg:none` is a SEPARATE weakness (improper signature verification, below).
  {
    cwe: 'CWE-347',
    match: (t) =>
      (has(t, 'alg confusion', 'algorithm confusion', 'key confusion') ||
        (has(t, 'rs256', 'es256', 'ps256', 'rsa', 'asymmetric') && has(t, 'hs256', 'hmac'))) &&
      has(t, 'jwt', 'jws', 'token', 'rs256', 'es256', 'hs256', 'asymmetric'),
  },
  // JWT alg:none / unsigned / missing signature verification → CWE-347.
  {
    cwe: 'CWE-347',
    match: (t) =>
      has(t, 'alg none', 'alg:none', 'alg=none', 'none algorithm', 'unsigned token') ||
      (has(t, 'signature') && has(t, 'not verified', 'unverified', 'missing', 'skipped', 'bypass')),
  },
  // Sensitive data written to logs → CWE-532.
  {
    cwe: 'CWE-532',
    match: (t) =>
      has(t, 'log leak', 'logging') && has(t, 'sensitive', 'secret', 'credential', 'token', 'password', 'pii'),
  },
  // Reflected / stored / DOM XSS → CWE-79.
  {
    cwe: 'CWE-79',
    match: (t) => has(t, 'xss', 'cross-site scripting', 'cross site scripting'),
  },
  // CSRF → CWE-352.
  {
    cwe: 'CWE-352',
    match: (t) => has(t, 'csrf', 'cross-site request forgery', 'cross site request forgery'),
  },
  // IDOR / horizontal access control → CWE-639.
  {
    cwe: 'CWE-639',
    match: (t) => has(t, 'idor', 'insecure direct object', 'horizontal') && !has(t, 'vertical', 'privilege escalation'),
  },
  // Vertical privilege escalation / missing function-level authz → CWE-269.
  {
    cwe: 'CWE-269',
    match: (t) =>
      has(t, 'privilege escalation', 'privesc', 'vertical') ||
      (has(t, 'function level', 'function-level') && has(t, 'authoriz')),
  },
  // XXE → CWE-611.
  {
    cwe: 'CWE-611',
    match: (t) => has(t, 'xxe', 'xml external entity', 'external entity'),
  },
  // Insecure deserialization → CWE-502.
  {
    cwe: 'CWE-502',
    match: (t) => has(t, 'deserializ', 'deserialisation', 'unsafe deserialization'),
  },
  // CORS misconfiguration → CWE-942.
  {
    cwe: 'CWE-942',
    match: (t) => has(t, 'cors') && has(t, 'misconfig', 'wildcard', 'permissive', '*'),
  },
];

/**
 * Lowercase + collapse the mechanism text fields on `raw` into one searchable
 * string. Underscores → spaces so `open_redirect` matches the `open redirect`
 * rule.
 */
function mechanismText(raw: Record<string, unknown>): string {
  return MECHANISM_TEXT_KEYS.map((k) => {
    const v = raw[k];
    return typeof v === 'string' ? v : '';
  })
    .join(' ')
    .toLowerCase()
    .replace(/_+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Resolve the CWE for a finding: explicit raw CWE wins, then a mechanism match,
 * then the category default (with `inferred: true`). Pure + deterministic.
 */
export function resolveCwe(
  raw: Record<string, unknown>,
  _category: FindingCategory,
  defaultCwe: string,
): CweResolution {
  const explicit = explicitCwe(raw);
  if (explicit) return { cwe: explicit, inferred: false };

  const text = mechanismText(raw);
  if (text) {
    for (const rule of MECHANISM_RULES) {
      if (rule.match(text)) return { cwe: rule.cwe, inferred: false };
    }
  }
  return { cwe: defaultCwe, inferred: true };
}
