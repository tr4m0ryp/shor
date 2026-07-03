// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Tiered, truncation-aware structured-output recovery ladder (spec T13 / F14).
 *
 * Ordering is load-bearing:
 *   (1) an SDK-provided structured object is validated, never repaired;
 *   (1b) raw text that already IS valid JSON is parsed as-is;
 *   (2) TRUNCATION IS CHECKED BEFORE any `jsonrepair` — a cut-off findings array
 *       must not be "closed" by inventing brackets (that silently drops findings
 *       = a false all-clear for a scanner). Truncation is salvaged by dropping the
 *       incomplete trailing element, or routed to a re-run; it is NEVER fabricated;
 *   (3) only a COMPLETE-but-malformed body is passed through `jsonrepair`;
 *   every repaired value is re-validated against the FULL schema and flagged.
 *
 * This module is PURE (no model calls). Re-run / reask (tier 4) is driven by the
 * caller, which owns the model handle; `buildReaskInstruction` gives it the
 * corrective suffix to append.
 */

import { coerceJson, extractJsonCandidate, salvageArrayPrefix, tryParse } from './local.js';

/**
 * Minimal validator surface — Zod's `.safeParse` satisfies it structurally, so a
 * caller passes a Zod schema directly with no import coupling. When absent, the
 * ladder can only assert object-shape (full-schema re-validation is skipped and
 * the result is flagged accordingly).
 */
export interface StructuredValidator<T> {
  safeParse(data: unknown): { success: true; data: T } | { success: false; error: unknown };
}

/** How a value was obtained — attached to every OK outcome for audit/logging. */
export type RepairMethod = 'sdk' | 'parsed-raw' | 'jsonrepair' | 'salvaged-array-prefix';

/** Provenance flag stamped onto a recovered value. */
export interface RepairMeta {
  /** True if any local coercion/salvage ran (false only for the untouched SDK object). */
  repaired: boolean;
  method: RepairMethod;
  /** True when the source output was truncated and a valid prefix was salvaged. */
  truncated: boolean;
  /** True when no full-schema validator was available (object-shape check only). */
  schemaValidated: boolean;
}

/** Discriminated result of a single local-recovery attempt. */
export type LocalRepairOutcome<T> =
  | { status: 'ok'; value: T; meta: RepairMeta }
  | { status: 'truncated'; reason: string; diagnostic: string }
  | { status: 'invalid'; reason: string; diagnostic: string }
  | { status: 'irreparable'; reason: string; diagnostic: string };

/** Inputs for {@link attemptLocalRepair}. */
export interface LocalRepairInput<T> {
  /** Final assistant text (the raw JSON-ish body); `null`/`undefined` when absent. */
  rawText: string | null | undefined;
  /** SDK-validated structured output, if the SDK captured one. */
  structured?: unknown;
  /** Provider stop/finish reason, if surfaced (`max_tokens` / `length` => truncated). */
  stopReason?: string | null | undefined;
  /** Full-schema validator (a Zod schema). Optional — see {@link RepairMeta.schemaValidated}. */
  validator?: StructuredValidator<T> | undefined;
}

const TRUNCATION_STOPS = new Set(['max_tokens', 'length', 'model_max_output_tokens', 'max_output_tokens']);

/** True when a provider stop reason denotes an output-length cut-off. */
export function isTruncationStop(stopReason: string | null | undefined): boolean {
  if (!stopReason) return false;
  const s = stopReason.toLowerCase();
  return TRUNCATION_STOPS.has(s) || s.includes('max_tokens') || s.includes('max_output');
}

function snippet(text: string): string {
  const t = text.trim();
  return t.length > 240 ? `${t.slice(0, 240)}…` : t;
}

function describeError(error: unknown): string {
  if (error && typeof error === 'object' && 'message' in error) {
    const m = (error as { message?: unknown }).message;
    if (typeof m === 'string') return m;
  }
  return String(error);
}

/** Full-schema validate, or object-shape fallback when no validator is supplied. */
function runValidate<T>(
  value: unknown,
  validator: StructuredValidator<T> | undefined,
): { ok: true; data: T; schemaValidated: boolean } | { ok: false; error: string } {
  if (!validator) {
    if (value !== null && typeof value === 'object') {
      return { ok: true, data: value as T, schemaValidated: false };
    }
    return { ok: false, error: 'parsed value is not an object' };
  }
  const r = validator.safeParse(value);
  if (r.success) return { ok: true, data: r.data, schemaValidated: true };
  return { ok: false, error: describeError(r.error) };
}

function ok<T>(value: T, method: RepairMethod, truncated: boolean, schemaValidated: boolean): LocalRepairOutcome<T> {
  return { status: 'ok', value, meta: { repaired: method !== 'sdk', method, truncated, schemaValidated } };
}

/**
 * Run the local ladder (tiers 1–3). Returns an OK value, or a non-OK status the
 * caller uses to decide on a bounded reask/re-run (tier 4).
 */
export function attemptLocalRepair<T>(input: LocalRepairInput<T>): LocalRepairOutcome<T> {
  const { rawText, structured, stopReason, validator } = input;

  // Tier 1: a present SDK object is the well-formed path — validate, never repair.
  if (structured !== undefined && structured !== null && typeof structured === 'object') {
    const v = runValidate(structured, validator);
    if (v.ok) return ok(v.data, 'sdk', false, v.schemaValidated);
    // Present but fails the FULL schema -> fall through to raw-text recovery.
  }

  const text = typeof rawText === 'string' ? rawText : '';
  const candidate = extractJsonCandidate(text);
  if (!candidate) {
    return { status: 'irreparable', reason: 'no JSON container found in output', diagnostic: snippet(text) };
  }

  const truncated = isTruncationStop(stopReason) || !candidate.terminated;

  // Tier 1b: the raw text already IS valid JSON (SDK just did not capture it).
  if (candidate.terminated) {
    const parsed = tryParse(candidate.text);
    if (parsed.ok) {
      const v = runValidate(parsed.value, validator);
      if (v.ok) return ok(v.data, 'parsed-raw', false, v.schemaValidated);
    }
  }

  // Tier 2: TRUNCATION FIRST. Do NOT let jsonrepair fabricate closers here.
  if (truncated) {
    const salvaged = salvageArrayPrefix(candidate.text);
    if (salvaged) {
      const parsed = tryParse(salvaged);
      if (parsed.ok) {
        const v = runValidate(parsed.value, validator);
        if (v.ok) return ok(v.data, 'salvaged-array-prefix', true, v.schemaValidated);
      }
    }
    return {
      status: 'truncated',
      reason: stopReason ? `output truncated (stop_reason=${stopReason})` : 'output truncated (unterminated JSON)',
      diagnostic: snippet(candidate.text),
    };
  }

  // Tier 3: complete-but-malformed -> jsonrepair, then re-validate against the FULL schema.
  const coerced = coerceJson(candidate.text);
  if (coerced.ok) {
    const v = runValidate(coerced.value, validator);
    if (v.ok) return ok(v.data, 'jsonrepair', false, v.schemaValidated);
    return {
      status: 'invalid',
      reason: `repaired JSON failed schema: ${v.error}`,
      diagnostic: snippet(candidate.text),
    };
  }
  return { status: 'irreparable', reason: 'could not parse or repair JSON', diagnostic: snippet(candidate.text) };
}

/**
 * Corrective suffix appended to the prompt for a bounded reask/re-run (tier 4).
 * Truncation asks for a shorter, complete answer; a schema failure feeds the
 * validator error back so the model can self-correct.
 */
export function buildReaskInstruction<T>(outcome: LocalRepairOutcome<T>): string {
  if (outcome.status === 'truncated') {
    return (
      'Your previous reply was cut off before the JSON finished. Reply again with the ' +
      'COMPLETE, valid JSON object only — no prose, no code fences. If the content is large, ' +
      'be more concise so the whole object fits in one reply.'
    );
  }
  const reason = outcome.status === 'ok' ? '' : outcome.reason;
  return (
    'Your previous reply was not valid JSON for the required schema ' +
    `(${reason}). Reply again with ONLY a single valid JSON object that matches the schema — ` +
    'no prose, no markdown, no code fences, no trailing commas.'
  );
}
