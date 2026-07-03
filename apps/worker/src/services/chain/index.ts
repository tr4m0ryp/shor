// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * services/chain — the capability-chaining engine (spec T11, F7, F8).
 *
 * Pipeline: a primitive LEDGER (privilege × side-effect) → a proximity-ranked
 * goal HUNT (end-states stated backward, "one primitive away" floats up) → a
 * COMPOSABILITY gate (a chain is complete only if adjacent primitives share a
 * REAL dataflow edge from task 015's CPG) → DYNAMIC confirmation via the OOB
 * oracle (006/008). The composability + dynamic proof are the differentiators
 * over Ali's tag-only matching, which reports causally-unrelated chains complete.
 *
 * Flag-gated (`SHOR_CHAIN`, default OFF) + fail-open: with the flag unset
 * `runChaining` returns nothing, so a stock scan is unchanged.
 */

import { huntGoals, toCandidateChain, DEFAULT_GOALS } from "./goal-hunt.js";
import { PrimitiveLedger } from "./ledger.js";
import { checkComposability, deriveDataflowEdges } from "./composability.js";
import type { TaintObservation } from "../taint/types.js";
import type {
	CandidateChain,
	ChainProof,
	ChainVerdict,
	DataflowEdge,
	Goal,
	Primitive,
	Privilege,
	SideEffect,
} from "./types.js";

/** Master flag: the chaining engine stays OFF unless explicitly enabled. */
export function chainEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
	return env.SHOR_CHAIN === "1";
}

/** Options for {@link evaluateChain}: supply edges directly or derive from taint. */
export interface EvaluateChainOptions {
	/** Explicit dataflow edges (e.g. a nonce-validation edge). */
	readonly edges?: readonly DataflowEdge[];
	/** Taint observations to derive stored-flow edges from (used when `edges` absent). */
	readonly observations?: readonly TaintObservation[];
	/** Dynamic confirmation hook (OOB via 006/008). Absent ⇒ stop at `composable`. */
	readonly confirm?: (chain: CandidateChain) => Promise<ChainProof>;
}

/**
 * Evaluate one candidate chain to a verdict. Composability is required FIRST: a
 * chain with any non-composing pair is `unproven` (we never assert on tags). A
 * composable chain with no dynamic hook is `composable` (static proof only); with
 * a hook it is `confirmed` iff the dynamic proof fires, else `inconclusive`.
 */
export async function evaluateChain(
	chain: CandidateChain,
	opts: EvaluateChainOptions = {},
): Promise<ChainVerdict> {
	const edges = opts.edges ?? (opts.observations ? deriveDataflowEdges(opts.observations) : []);
	const composition = checkComposability(chain, edges);

	if (!composition.composable) {
		const reason =
			composition.links.find((l) => !l.composable)?.reason ??
			"no composable dataflow edge between primitives";
		return { goal: chain.goal, status: "unproven", composition, reason };
	}
	if (!opts.confirm) {
		return {
			goal: chain.goal,
			status: "composable",
			composition,
			reason: "real dataflow edge on every pair; dynamic confirmation not run",
		};
	}
	const dynamic = await opts.confirm(chain);
	return {
		goal: chain.goal,
		status: dynamic.status === "confirmed" ? "confirmed" : "inconclusive",
		composition,
		dynamic,
		reason: dynamic.detail,
	};
}

/** Map a stored value's eventual sink class to the consumer's side-effect. */
function consumerSideEffect(vulnClass: string): SideEffect {
	const v = vulnClass.toLowerCase();
	if (v.includes("xss") || v.includes("render") || v.includes("html")) return "render";
	if (v.includes("ssrf") || v.includes("redirect") || v.includes("fetch")) return "redirect";
	if (v.includes("auth") || v.includes("session") || v.includes("token")) return "auth_transition";
	return "state_read";
}

/** Options for {@link primitivesFromTaint}. */
export interface FromTaintOptions {
	/** Privilege the store-write is attributed to (default `low_priv`). */
	readonly writerPrivilege?: Privilege;
	/** Privilege the render/read fires in (default `high_priv`). */
	readonly renderPrivilege?: Privilege;
}

/**
 * Derive producer + consumer primitives from second-order taint observations.
 * Each stored flow yields a `state_write` producer (attacker persists) and a
 * consumer keyed to the same store (the render/read the stored value reaches) —
 * so `deriveDataflowEdges` over the SAME observations composes them, because the
 * CPG already proved the bridge. Direct flows are single primitives, not chain
 * bridges, so they are skipped here.
 */
export function primitivesFromTaint(
	observations: readonly TaintObservation[],
	opts: FromTaintOptions = {},
): Primitive[] {
	const writer = opts.writerPrivilege ?? "low_priv";
	const render = opts.renderPrivilege ?? "high_priv";
	const out: Primitive[] = [];
	for (const o of observations) {
		if (o.flowKind !== "second_order" || !o.throughStore) continue;
		out.push({
			id: `chain-write-${o.id}`,
			privilege: writer,
			sideEffect: "state_write",
			vulnClass: o.vulnClass,
			summary: `attacker-controlled input persisted to store '${o.throughStore}'`,
			store: o.throughStore,
			source: o.source,
			sink: o.source,
			taintObservationId: o.id,
		});
		out.push({
			id: `chain-read-${o.id}`,
			privilege: render,
			sideEffect: consumerSideEffect(o.vulnClass),
			vulnClass: o.vulnClass,
			summary: `value from store '${o.throughStore}' reaches a ${o.vulnClass} sink`,
			store: o.throughStore,
			sink: o.sink,
			taintObservationId: o.id,
		});
	}
	return out;
}

/** Options for {@link runChaining}. */
export interface RunChainingOptions extends EvaluateChainOptions {
	/** Goals to hunt (defaults to {@link DEFAULT_GOALS}). */
	readonly goals?: readonly Goal[];
	/** Force-enable/disable (defaults to {@link chainEnabled}). */
	readonly enabled?: boolean;
}

/**
 * Run the full engine over a populated ledger: hunt goals (proximity-ranked),
 * take each tag-complete candidate, and evaluate it (composability → dynamic
 * proof). Returns verdicts ordered by proximity. Flag-gated: OFF ⇒ empty.
 */
export async function runChaining(
	ledger: PrimitiveLedger,
	opts: RunChainingOptions = {},
): Promise<ChainVerdict[]> {
	const enabled = opts.enabled ?? chainEnabled();
	if (!enabled) return [];
	const goals = opts.goals ?? DEFAULT_GOALS;
	const verdicts: ChainVerdict[] = [];
	for (const match of huntGoals(goals, ledger)) {
		const chain = toCandidateChain(match);
		if (!chain) continue;
		verdicts.push(await evaluateChain(chain, opts));
	}
	return verdicts;
}

export { PrimitiveLedger } from "./ledger.js";
export {
	DEFAULT_GOALS,
	huntGoal,
	huntGoals,
	nextHunt,
	toCandidateChain,
} from "./goal-hunt.js";
export type { HuntDirective } from "./goal-hunt.js";
export {
	checkComposability,
	confirmChain,
	deriveDataflowEdges,
	findComposingEdge,
} from "./composability.js";
export type { ChainProofOps, ConfirmChainOptions } from "./composability.js";
export {
	PRIVILEGE_ORDER,
	privilegeRank,
	withinBand,
} from "./types.js";
export type {
	CandidateChain,
	ChainProof,
	ChainProofStatus,
	ChainStatus,
	ChainVerdict,
	CompositionLink,
	CompositionResult,
	DataflowEdge,
	Goal,
	GoalMatch,
	GoalStep,
	Primitive,
	Privilege,
	SideEffect,
	StepMatch,
} from "./types.js";
