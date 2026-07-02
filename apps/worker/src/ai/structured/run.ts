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
 */

import type { JsonSchemaOutputFormat } from '@anthropic-ai/claude-agent-sdk';
import type { AuditSession } from '../../audit/index.js';
import type { ActivityLogger } from '../../types/activity-logger.js';
import type { ProviderConfig } from '../../types/config.js';
import { type ClaudePromptResult, runClaudePrompt } from '../claude-executor/index.js';
import type { ModelTier } from '../models.js';

/** Inputs for {@link runStructured}: the prompt + the same optional plumbing `runClaudePrompt` accepts. */
export interface RunStructuredArgs {
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
}

/**
 * Discriminated result. `raw` is always the underlying {@link ClaudePromptResult}
 * (synthesized on the never-reached throw path) so callers can still inspect
 * tokens, duration, and the raw text.
 */
export type StructuredResult<T> =
  | { ok: true; value: T; raw: ClaudePromptResult }
  | { ok: false; error: string; raw: ClaudePromptResult };

/** No-op logger so `runStructured` is usable without wiring an ActivityLogger. */
const NOOP_LOGGER: ActivityLogger = {
  info: () => {},
  warn: () => {},
  error: () => {},
};

/**
 * Run one agent in JSON-schema structured-output mode and return a typed value.
 *
 * Never throws. Returns `ok: false` when the agent run failed, or when the SDK
 * produced no object-shaped `structuredOutput` (e.g. the model ignored the
 * schema). The SDK already validates `structuredOutput` against `schema`, so a
 * present, non-null object is taken as valid and cast to `T`.
 */
export async function runStructured<T>(args: RunStructuredArgs): Promise<StructuredResult<T>> {
  const {
    prompt,
    sourceDir,
    schema,
    modelTier = 'medium',
    agentName = null,
    auditSession = null,
    logger = NOOP_LOGGER,
    deliverablesSubdir,
    providerConfig,
    extraEnv,
    maxTurns,
  } = args;

  let raw: ClaudePromptResult;
  try {
    raw = await runClaudePrompt(
      prompt,
      sourceDir,
      '', // context — callers fold any preamble into `prompt`
      agentName ?? 'structured-output', // description: log + timer label
      agentName,
      auditSession,
      logger,
      modelTier,
      schema, // outputFormat — enables SDK JSON-schema structured output
      undefined, // apiKey — resolved from env / providerConfig downstream
      deliverablesSubdir,
      providerConfig,
      extraEnv,
      maxTurns,
    );
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
  if (structured === null || typeof structured !== 'object') {
    return { ok: false, error: 'missing or non-object structuredOutput', raw };
  }

  return { ok: true, value: structured as T, raw };
}

/**
 * Unwrap a {@link StructuredResult} or fall back. Enables fail-open defaults
 * (e.g. a dedup judge defaulting to `NEW` when structured output is absent).
 */
export function parseOr<T>(result: StructuredResult<T>, fallback: T): T {
  return result.ok ? result.value : fallback;
}
