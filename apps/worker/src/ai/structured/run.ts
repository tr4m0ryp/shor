// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Structured-output helper.
 *
 * Thin wrapper over `runClaudePrompt`'s existing `outputFormat` parameter (the
 * SDK's JSON-schema structured-output mode). It runs one agent, then surfaces
 * the SDK-validated `structuredOutput` as a typed value via a discriminated
 * result — so verifier / voter / judge / grader / oracle callers aggregate on
 * typed data instead of re-parsing prose.
 *
 * Contract: `runStructured` NEVER throws. Every failure path (agent failure,
 * missing/non-object structured output, or an unexpected throw from the runner)
 * collapses to `{ ok: false }`, leaving callers free to fail open with
 * `parseOr`.
 *
 * Truncation-aware auto-repair (spec T13): OPT-IN via `SHOR_STRUCTURED_REPAIR=1`.
 * When enabled AND the SDK produced no valid object, a zero-cost local ladder
 * (Zod safeParse -> truncation check -> jsonrepair -> salvage) runs BEFORE any
 * re-inference; a truncated body is never "closed" by fabricating brackets. With
 * the flag OFF — or a well-formed response — behaviour is byte-for-byte as before.
 */

import type { JsonSchemaOutputFormat } from '@anthropic-ai/claude-agent-sdk';
import type { AuditSession } from '../../audit/index.js';
import type { ActivityLogger } from '../../types/activity-logger.js';
import type { ProviderConfig } from '../../types/config.js';
import { type ClaudePromptResult, runClaudePrompt } from '../claude-executor/index.js';
import type { ModelTier } from '../models.js';
import {
  attemptLocalRepair,
  buildReaskInstruction,
  type LocalRepairOutcome,
  type RepairMeta,
  type StructuredValidator,
} from './repair/index.js';

export type { RepairMeta, StructuredValidator } from './repair/index.js';

/** Inputs for {@link runStructured}: the prompt + the same optional plumbing `runClaudePrompt` accepts. */
export interface RunStructuredArgs<T = unknown> {
  /** The instruction to send to the agent. Any context is expected to be folded in by the caller. */
  prompt: string;
  /** Working directory the agent runs in (its `cwd`). */
  sourceDir: string;
  /** JSON-schema output format passed straight to the SDK as `outputFormat`. */
  schema: JsonSchemaOutputFormat;
  /** Model tier; defaults to `'medium'` to match `runClaudePrompt`. */
  modelTier?: ModelTier;
  /** Owning agent name, used for skill attribution and as the log/timer label. */
  agentName?: string | null;
  /** Audit session for transcript capture, or `null` to skip. */
  auditSession?: AuditSession | null;
  /** Structured logger; defaults to a no-op so the helper is callable without one. */
  logger?: ActivityLogger;
  /** Relative deliverables subdirectory the SDK env points the agent at. */
  deliverablesSubdir?: string;
  /** Provider/model overrides forwarded to the SDK env. */
  providerConfig?: ProviderConfig;
  /** Extra environment variables forwarded to the SDK subprocess. */
  extraEnv?: Record<string, string>;
  /** Per-run turn cap; defaults to the runner's 10_000. Screen voters pass a low cap so a screen can't run away. */
  maxTurns?: number;
  /**
   * Full-schema Zod validator for the auto-repair path. Zod's `.safeParse`
   * satisfies {@link StructuredValidator} structurally, so pass a Zod schema
   * directly. When omitted, repaired output is validated for object-shape only
   * (see {@link RepairMeta.schemaValidated}). Ignored unless repair is enabled.
   */
  validator?: StructuredValidator<T>;
  /** Bounded reask/re-run attempts on the repair path (tier 4). Default 2. */
  maxRepairAttempts?: number;
}

/**
 * Discriminated result. `raw` is always the underlying {@link ClaudePromptResult}
 * (synthesized on the never-reached throw path) so callers can still inspect
 * tokens, duration, and the raw text. `repair` is present only when the value
 * came back through the auto-repair ladder (never on the stock path).
 */
export type StructuredResult<T> =
  | { ok: true; value: T; raw: ClaudePromptResult; repair?: RepairMeta }
  | { ok: false; error: string; raw: ClaudePromptResult };

/** No-op logger so `runStructured` is usable without wiring an ActivityLogger. */
const NOOP_LOGGER: ActivityLogger = {
  info: () => {},
  warn: () => {},
  error: () => {},
};

/** Default bounded reask/re-run attempts (tier 4) on the repair path. */
const DEFAULT_REPAIR_ATTEMPTS = 2;

/** Auto-repair is OFF unless explicitly enabled; a stock scan is unchanged. */
function repairEnabled(): boolean {
  return process.env.SHOR_STRUCTURED_REPAIR === '1';
}

/**
 * `stop_reason` is captured by the SDK result handler but not (yet) part of the
 * `ClaudePromptResult` surface; read it opportunistically so the ladder can use
 * it when a future change threads it through. Structural truncation detection is
 * the always-available fallback. (Provider-side: threading `stop_reason` from
 * `ResultData` -> `ClaudePromptResult`, and raising DeepSeek `max_tokens` on a
 * truncated re-run, are the remaining constrained-decoding seams — spec scope.)
 */
function readStopReason(raw: ClaudePromptResult): string | null {
  const r = raw as { stop_reason?: string | null };
  return typeof r.stop_reason === 'string' ? r.stop_reason : null;
}

/** Positional call into the low-level runner, isolated so the reask loop can reuse it. */
function invokeAgent(args: RunStructuredArgs, prompt: string): Promise<ClaudePromptResult> {
  return runClaudePrompt(
    prompt,
    args.sourceDir,
    '', // context — callers fold any preamble into `prompt`
    args.agentName ?? 'structured-output', // description: log + timer label
    args.agentName ?? null,
    args.auditSession ?? null,
    args.logger ?? NOOP_LOGGER,
    args.modelTier ?? 'medium',
    args.schema, // outputFormat — enables SDK JSON-schema structured output
    undefined, // apiKey — resolved from env / providerConfig downstream
    args.deliverablesSubdir,
    args.providerConfig,
    args.extraEnv,
    args.maxTurns,
  );
}

function outcomeError<T>(outcome: LocalRepairOutcome<T>): string {
  return outcome.status === 'ok' ? '' : `${outcome.status}: ${outcome.reason}`;
}

/**
 * Run one agent in JSON-schema structured-output mode and return a typed value.
 *
 * Never throws. Returns `ok: false` when the agent run failed, or when no valid
 * object could be produced. With `SHOR_STRUCTURED_REPAIR=1`, a missing/malformed
 * body is routed through the local repair ladder (and a bounded reask) before
 * giving up; the well-formed and flag-off paths are unchanged.
 */
export async function runStructured<T>(args: RunStructuredArgs<T>): Promise<StructuredResult<T>> {
  const { validator, maxRepairAttempts = DEFAULT_REPAIR_ATTEMPTS } = args;

  let raw: ClaudePromptResult;
  try {
    raw = await invokeAgent(args, args.prompt);
  } catch (error) {
    // `runClaudePrompt` is designed to swallow its own errors, but guard anyway
    // so `runStructured` upholds its never-throws contract for every caller.
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, error: message, raw: { success: false, duration: 0, error: message } };
  }

  if (!raw.success) {
    return { ok: false, error: raw.error ?? 'agent run failed', raw };
  }

  const structured = raw.structuredOutput;
  const structuredOk = structured !== null && typeof structured === 'object';

  // Well-formed fast path — identical to prior behaviour. A validator, when
  // supplied, tightens the SDK's draft-07 check to the full Zod schema; a pass
  // returns immediately with no repair flag.
  if (structuredOk) {
    if (!validator) return { ok: true, value: structured as T, raw };
    const v = validator.safeParse(structured);
    if (v.success) return { ok: true, value: v.data, raw };
    // SDK object present but fails the full schema -> fall through to repair.
  }

  // Repair disabled -> preserve today's fail-open behaviour exactly.
  if (!repairEnabled()) {
    return { ok: false, error: 'missing or non-object structuredOutput', raw };
  }

  // === Local repair ladder (tiers 1–3), then a bounded reask/re-run (tier 4). ===
  let outcome = attemptLocalRepair<T>({
    rawText: raw.result,
    structured,
    stopReason: readStopReason(raw),
    validator,
  });
  if (outcome.status === 'ok') return { ok: true, value: outcome.value, raw, repair: outcome.meta };

  for (let attempt = 0; attempt < maxRepairAttempts; attempt++) {
    const reask = `${args.prompt}\n\n${buildReaskInstruction(outcome)}`;
    let retry: ClaudePromptResult;
    try {
      retry = await invokeAgent(args, reask);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { ok: false, error: message, raw };
    }
    if (!retry.success) return { ok: false, error: retry.error ?? outcomeError(outcome), raw: retry };
    raw = retry;
    outcome = attemptLocalRepair<T>({
      rawText: raw.result,
      structured: raw.structuredOutput,
      stopReason: readStopReason(raw),
      validator,
    });
    if (outcome.status === 'ok') return { ok: true, value: outcome.value, raw, repair: outcome.meta };
  }

  return { ok: false, error: outcomeError(outcome), raw };
}

/**
 * Unwrap a {@link StructuredResult} or fall back. Enables fail-open defaults
 * (e.g. a dedup judge defaulting to `NEW` when structured output is absent).
 */
export function parseOr<T>(result: StructuredResult<T>, fallback: T): T {
  return result.ok ? result.value : fallback;
}
