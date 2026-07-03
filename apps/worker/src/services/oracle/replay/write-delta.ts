// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Real state-change proof — the write before/after delta (T7 / F4d).
 *
 * A genuine "we changed server state" proof is NOT "the write returned 200". It is:
 *   1. mint a fresh, unique nonce;
 *   2. PRE-READ to assert the nonce is ABSENT (so its later presence is attributable
 *      to OUR write, not a pre-existing value or a reflected echo);
 *   3. write the nonce (as the attacker identity);
 *   4. read it back through an INDEPENDENT identity/channel (proves the value
 *      persisted and is visible to a second principal — a genuine before/after delta).
 *
 * This module owns the ordered sequence + the pure verdict + the RoE write gate. The
 * actual HTTP writes are INJECTED ops so the sequence is unit-testable and so the live
 * wiring (which fires a mutating request) lands in task 008 — behind the same gate.
 * Default OFF: absent `SHOR_ORACLE_WRITE_DELTA`, no write is ever attempted.
 */

import { randomUUID } from 'node:crypto';

/** RoE write-allowed flag. Unset / falsey ⇒ write-delta stays OFF (read-only scan). */
export const WRITE_DELTA_ENV = 'SHOR_ORACLE_WRITE_DELTA';

const TRUTHY: ReadonlySet<string> = new Set(['1', 'true', 'yes', 'on']);

/** Whether the RoE permits the mutating write-delta probe (flag-gated, default OFF). */
export function writeDeltaEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env[WRITE_DELTA_ENV]?.trim().toLowerCase();
  return raw !== undefined && TRUTHY.has(raw);
}

/** Mint a fresh, unique, greppable nonce for one write-delta attempt. */
export function mintNonce(): string {
  return `shor-nonce-${randomUUID()}`;
}

/** 3-valued outcome of a write-delta probe. */
export type WriteDeltaVerdict = 'confirmed' | 'not_confirmed' | 'inconclusive';

/** Non-secret detail of why a write-delta landed where it did. */
export type WriteDeltaReason =
  | 'disabled'
  | 'infra_incomplete'
  | 'nonce_pre_existing'
  | 'write_rejected'
  | 'nonce_appeared'
  | 'nonce_absent_after_write';

/**
 * One observed step of the sequence.
 *   - `observed` — did the step complete (transport OK)? false ⇒ infra failure.
 *   - `present`  — for a READ: was the nonce in the response? for a WRITE: was it
 *                  accepted (2xx / success)?
 */
export interface StepResult {
  readonly observed: boolean;
  readonly present: boolean;
}

/** The three observations the verdict is reduced from. */
export interface WriteDeltaObservations {
  readonly preRead: StepResult;
  readonly write: StepResult;
  readonly readBack: StepResult;
}

export interface WriteDeltaDecision {
  readonly verdict: WriteDeltaVerdict;
  readonly reason: WriteDeltaReason;
}

/**
 * Pure reduction of the three observations to a verdict. Order matters — the pre-read
 * gate dominates:
 *   - pre-read not observed          ⇒ inconclusive (could not establish the baseline)
 *   - nonce PRESENT before the write ⇒ not_confirmed (cannot attribute — the #1 FP)
 *   - write not observed             ⇒ inconclusive
 *   - write rejected                 ⇒ not_confirmed (no change happened)
 *   - read-back not observed         ⇒ inconclusive
 *   - nonce present after the write  ⇒ confirmed (genuine cross-identity delta)
 *   - nonce absent after the write   ⇒ not_confirmed (claimed success, nothing changed)
 * Fail-open: infra gaps are inconclusive, NEVER a refutation of the underlying finding.
 */
export function decideWriteDelta(obs: WriteDeltaObservations): WriteDeltaDecision {
  if (!obs.preRead.observed) return { verdict: 'inconclusive', reason: 'infra_incomplete' };
  if (obs.preRead.present) return { verdict: 'not_confirmed', reason: 'nonce_pre_existing' };
  if (!obs.write.observed) return { verdict: 'inconclusive', reason: 'infra_incomplete' };
  if (!obs.write.present) return { verdict: 'not_confirmed', reason: 'write_rejected' };
  if (!obs.readBack.observed) return { verdict: 'inconclusive', reason: 'infra_incomplete' };
  if (obs.readBack.present) return { verdict: 'confirmed', reason: 'nonce_appeared' };
  return { verdict: 'not_confirmed', reason: 'nonce_absent_after_write' };
}

/**
 * The injected write/read operations for one attempt. The caller (008) binds these to
 * the executor + identities: `write` fires as the attacker identity, `readBack` fires
 * as a DISTINCT independent identity/channel so the delta is proven cross-principal.
 */
export interface WriteDeltaOps {
  /** Read the target and report whether `nonce` is present (pre-read: expect ABSENT). */
  preRead(nonce: string): Promise<StepResult>;
  /** Write `nonce` as the attacker identity; `present` ⇒ the write was accepted. */
  write(nonce: string): Promise<StepResult>;
  /** Read back via an INDEPENDENT identity/channel; `present` ⇒ the nonce is visible. */
  readBack(nonce: string): Promise<StepResult>;
}

/** Tunables for {@link runWriteDelta}. */
export interface WriteDeltaOptions {
  /** Override the minted nonce (tests). */
  readonly nonce?: string;
  /** Override the RoE gate (defaults to {@link writeDeltaEnabled}). */
  readonly enabled?: boolean;
}

export interface WriteDeltaResult extends WriteDeltaDecision {
  /** The nonce this attempt used (greppable marker, not a secret). */
  readonly nonce: string;
}

const SKIPPED: StepResult = { observed: false, present: false };

async function safeStep(fn: () => Promise<StepResult>): Promise<StepResult> {
  try {
    return await fn();
  } catch {
    // Fail-open: a thrown op is an unobserved step (infra), never a refutation.
    return SKIPPED;
  }
}

/**
 * Drive the ordered write-delta sequence over injected ops and return the verdict.
 * The write is skipped unless the pre-read cleanly asserts absence, and the read-back
 * is skipped unless the write was accepted — so a mutating request never fires once
 * the proof is already decided (and never at all when the RoE gate is OFF).
 */
export async function runWriteDelta(
  ops: WriteDeltaOps,
  options: WriteDeltaOptions = {},
): Promise<WriteDeltaResult> {
  const nonce = options.nonce ?? mintNonce();
  const enabled = options.enabled ?? writeDeltaEnabled();
  if (!enabled) return { verdict: 'inconclusive', reason: 'disabled', nonce };

  const preRead = await safeStep(() => ops.preRead(nonce));
  let write: StepResult = SKIPPED;
  let readBack: StepResult = SKIPPED;
  if (preRead.observed && !preRead.present) {
    write = await safeStep(() => ops.write(nonce));
    if (write.observed && write.present) {
      readBack = await safeStep(() => ops.readBack(nonce));
    }
  }
  return { ...decideWriteDelta({ preRead, write, readBack }), nonce };
}
