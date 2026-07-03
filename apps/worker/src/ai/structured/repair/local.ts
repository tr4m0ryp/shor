// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Zero-cost local JSON repair primitives (spec T13 / F14).
 *
 * Pure, deterministic helpers that recover structured output from raw model
 * text WITHOUT a second model call. The critical invariant lives in the ladder,
 * not here: `coerceJson` (which calls `jsonrepair`) will happily fabricate
 * closing brackets for a TRUNCATED array — so the ladder MUST establish that the
 * text is complete before using it. `salvageArrayPrefix` is the truncation-safe
 * counterpart: it only ever DROPS an incomplete trailing element, never invents.
 */

import { jsonrepair } from 'jsonrepair';

/** A JSON value located inside (possibly prose-wrapped) model output. */
export interface JsonCandidate {
  /** The extracted candidate text (from the first bracket onward). */
  text: string;
  /** True when the value's brackets balance before EOF; false = unterminated (truncated). */
  terminated: boolean;
}

const WS = /\s/;

/** Strip a single leading/trailing markdown code fence (handles a fence with no closer). */
function stripFences(text: string): string {
  let t = text.trim();
  const open = /^```[a-zA-Z0-9]*[ \t]*\r?\n?/;
  if (open.test(t)) {
    t = t.replace(open, '').replace(/\r?\n?```[ \t]*$/, '');
  }
  return t.trim();
}

/** Index of the first `{` or `[`, or -1 if the text holds no JSON container. */
function firstBracket(text: string): number {
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '{' || text[i] === '[') return i;
  }
  return -1;
}

/**
 * Scan a string literal starting at the opening quote `i`. Returns the index
 * just past the closing quote, or -1 if the string never closes (truncated).
 */
function scanString(t: string, i: number): number {
  let esc = false;
  for (let j = i + 1; j < t.length; j++) {
    const c = t[j];
    if (esc) {
      esc = false;
    } else if (c === '\\') {
      esc = true;
    } else if (c === '"') {
      return j + 1;
    }
  }
  return -1;
}

/**
 * Scan a balanced `{...}` / `[...]` starting at `start`. Returns the index just
 * past the matching close, or -1 if depth never returns to zero (truncated).
 * String- and escape-aware so braces inside strings do not shift the depth.
 */
export function scanBalanced(t: string, start: number): number {
  let depth = 0;
  for (let i = start; i < t.length; i++) {
    const ch = t[i];
    if (ch === '"') {
      const end = scanString(t, i);
      if (end < 0) return -1;
      i = end - 1;
      continue;
    }
    if (ch === '{' || ch === '[') depth++;
    else if (ch === '}' || ch === ']') {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

/** Scan one array element value at `i`. Returns end index, or -1 if truncated. */
function scanValue(t: string, i: number): number {
  const ch = t[i];
  if (ch === '{' || ch === '[') return scanBalanced(t, i);
  if (ch === '"') return scanString(t, i);
  // Primitive (number / true / false / null): read to the next delimiter.
  let j = i;
  while (j < t.length && t[j] !== ',' && t[j] !== ']' && t[j] !== '}' && !WS.test(t[j] as string)) {
    j++;
  }
  // A primitive that runs to EOF may itself be truncated (e.g. `123` was `1234`).
  return j >= t.length ? -1 : j;
}

/**
 * Extract the first JSON container from model text, stripping code fences and
 * surrounding prose. `terminated` reports whether it closes before EOF.
 */
export function extractJsonCandidate(text: string): JsonCandidate | null {
  const stripped = stripFences(text);
  const start = firstBracket(stripped);
  if (start < 0) return null;
  const end = scanBalanced(stripped, start);
  if (end < 0) return { text: stripped.slice(start), terminated: false };
  return { text: stripped.slice(start, end), terminated: true };
}

/** `JSON.parse` guarded — never throws. */
export function tryParse(text: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false };
  }
}

/**
 * Repair a COMPLETE-but-malformed JSON string (fences already removed): direct
 * parse first, then `jsonrepair` (trailing commas, single quotes, unquoted keys,
 * comments, ...). MUST NOT be called on truncated text — `jsonrepair` would
 * invent closers and silently drop the cut-off tail. That gate lives in the
 * ladder; this function is deliberately unaware of truncation.
 */
export function coerceJson(text: string): { ok: true; value: unknown } | { ok: false } {
  const direct = tryParse(text);
  if (direct.ok) return direct;
  try {
    const repaired = jsonrepair(text);
    const parsed = tryParse(repaired);
    if (parsed.ok) return parsed;
  } catch {
    // jsonrepair throws JSONRepairError on hopeless input — fall through.
  }
  return { ok: false };
}

/**
 * Truncation-SAFE salvage for a top-level array: return `[ <complete elements> ]`,
 * dropping any incomplete trailing element. Returns null when the value is not an
 * array or no whole element survived. Never fabricates data — the opposite of
 * letting `jsonrepair` close a truncated array.
 */
export function salvageArrayPrefix(text: string): string | null {
  const t = text.trim();
  if (t[0] !== '[') return null;
  const elements: string[] = [];
  let i = 1;
  while (i < t.length) {
    while (i < t.length && (WS.test(t[i] as string) || t[i] === ',')) i++;
    if (i >= t.length || t[i] === ']') break;
    const end = scanValue(t, i);
    if (end < 0) break; // truncated element — stop, keep what came before.
    elements.push(t.slice(i, end));
    i = end;
  }
  if (elements.length === 0) return null;
  return `[${elements.join(',')}]`;
}
