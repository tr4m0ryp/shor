// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Shapes for guard-dominance analysis (spec T10, F9b) over the Joern CPG built by
 * task 015 — reused, never rebuilt.
 *
 * The question is NOT "does the code mention an auth check" (Ali's brittle regex
 * over agent prose) but a real CFG-dominator query: does an auth-check node
 * `dominate` the sensitive sink on EVERY path (Joern `dominatedBy`)? A sink with
 * no dominating guard is reachable by a path that skips the check → a missing
 * authorization (CWE-862). Structural dominance answers "a check runs"; the LLM
 * semantic layer answers WHAT it asserts (right resource, right verb) so a guard
 * that dominates but authorizes the wrong thing is still caught.
 *
 * Everything here is data-only: no engine coupling, so a `GuardFinding` serializes
 * to a deliverable and correlates with taint observations by location.
 */

import type { TaintPathStep } from "../types.js";

/** Structural (dominator-tree) verdict, before any semantic judgement. */
export type GuardStructuralVerdict =
	/** No guard call exists anywhere in the sink's method. */
	| "unguarded"
	/** A guard exists in the method but does NOT dominate the sink (bypassable path). */
	| "partial_guard"
	/** At least one guard dominates the sink on all paths. */
	| "guarded";

/** Final disposition after folding structure with the (optional) semantic layer. */
export type GuardDisposition =
	/** Sink reachable with no dominating authorization (unguarded or partial). */
	| "missing_guard"
	/** A guard dominates but does not authorize THIS resource/verb (semantic gap). */
	| "wrong_guard"
	/** A guard dominates and the LLM confirms it authorizes this operation. */
	| "adequate"
	/** Semantic layer could not decide; never asserted as a finding. */
	| "unproven";

/** A sink whose dominance relationship to candidate guards was computed. */
export interface GuardCandidate {
	/** Stable hash over (method, sink location) — the correlation key. */
	readonly id: string;
	/** The sensitive operation (state-change / privileged call) the CPG located. */
	readonly sink: TaintPathStep;
	/** Fully-qualified method the sink lives in. */
	readonly method?: string | undefined;
	/** Weakness class implied by a missing guard. */
	readonly vulnClass: string;
	/** CWE id (missing authorization). */
	readonly cwe: string;
	readonly structuralVerdict: GuardStructuralVerdict;
	/** Guard calls that dominate the sink on every path (the "a check runs" proof). */
	readonly dominatingGuards: readonly TaintPathStep[];
	/** Guard calls present in the method but bypassable (do NOT dominate the sink). */
	readonly nonDominatingGuards: readonly TaintPathStep[];
}

/**
 * The LLM's judgement of WHAT a dominating guard asserts. Pairs with structural
 * dominance so a right-guard-wrong-resource case (e.g. `isLoggedIn` dominates a
 * "delete ANY user's post" sink) is caught even though a check demonstrably runs.
 */
export interface GuardSemanticVerdict {
	/** Does the guard perform an authorization decision at all (not just presence)? */
	readonly assertsAuthorization: boolean;
	/** Does it bind the check to the SPECIFIC resource the sink touches (ownership)? */
	readonly resourceScoped: boolean;
	/** Does the authorized verb/action match the sink's operation? */
	readonly verbScoped: boolean;
	/** Short, non-secret rationale (no code snippets pooled). */
	readonly rationale: string;
}

/** A guard candidate resolved to a disposition (with the semantic verdict when consulted). */
export interface GuardFinding extends GuardCandidate {
	readonly disposition: GuardDisposition;
	readonly semantic?: GuardSemanticVerdict | undefined;
}

/** One entry of the raw JSON the generated dominance script emits. */
export interface GuardRawSink {
	readonly sink: TaintPathStep;
	readonly method?: string | undefined;
	readonly dominatingGuards?: readonly TaintPathStep[] | undefined;
	readonly nonDominatingGuards?: readonly TaintPathStep[] | undefined;
}

/** The full JSON payload the dominance script writes to its out-file. */
export interface GuardRawResult {
	readonly results?: readonly GuardRawSink[] | undefined;
}

/** Reason the analysis produced no findings without failing the scan. */
export interface GuardDominanceDegradation {
	readonly reason:
		| "disabled"
		| "no_cpg"
		| "joern_missing"
		| "query_failed";
	readonly detail: string;
}

/** Final result of the guard-dominance pass. `degraded` is set on any fail-open path. */
export interface GuardDominanceResult {
	readonly findings: readonly GuardFinding[];
	readonly degraded?: GuardDominanceDegradation;
}
