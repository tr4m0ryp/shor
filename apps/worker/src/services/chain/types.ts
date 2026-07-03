// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Shared shapes for the capability-chaining engine (spec T11, F7, F8).
 *
 * The engine combines sub-threshold PRIMITIVES (findings below the severity gate,
 * but chain fuel) toward high-impact goals. Every primitive is typed by a
 * privilege LATTICE position × a side-effect — the shared "pure detector over
 * typed observations" spine (F7). The differentiator over Ali's version: a chain
 * is NEVER declared complete on matching type tags alone (his fatal gap, which
 * declares causally-unrelated chains complete). Completion requires a REAL
 * dataflow edge between adjacent primitives (derived from task 015's CPG) AND a
 * dynamic confirmation via the OOB oracle (006/008). No edge ⇒ `unproven`.
 *
 * Data-only here (plus the lattice helpers); the ledger / hunt / composability
 * modules operate over these shapes so each is independently unit-testable.
 */

import type { TaintPathStep } from "../taint/types.js";

/**
 * The privilege lattice — the common definition of "is this a real escalation"
 * (F7). Ordered low→high; a chain that ends at a strictly higher rank than it
 * starts is an escalation.
 */
export type Privilege =
	| "unauth"
	| "self"
	| "low_priv"
	| "cross_user"
	| "high_priv"
	| "admin";

/** The observable effect a primitive produces. */
export type SideEffect =
	| "state_write" // persists attacker-influenced data
	| "state_read" // reads data back (potential exfil / second-order source)
	| "render" // renders stored data into a victim's response (XSS trigger)
	| "auth_transition" // changes auth/session/token/nonce state
	| "exec" // command / code execution
	| "redirect"; // open-redirect / SSRF pivot

/** Ordered lattice — index IS the rank. */
export const PRIVILEGE_ORDER: readonly Privilege[] = [
	"unauth",
	"self",
	"low_priv",
	"cross_user",
	"high_priv",
	"admin",
];

/** Numeric rank of a privilege (0 = unauth … 5 = admin); -1 if unknown. */
export function privilegeRank(p: Privilege): number {
	return PRIVILEGE_ORDER.indexOf(p);
}

/** Is `p` within the inclusive band [min, max]? Absent bounds are open. */
export function withinBand(p: Privilege, min?: Privilege, max?: Privilege): boolean {
	const r = privilegeRank(p);
	if (r < 0) return false;
	if (min && r < privilegeRank(min)) return false;
	if (max && r > privilegeRank(max)) return false;
	return true;
}

/** A sub-threshold finding usable as chain fuel, typed by privilege × side-effect. */
export interface Primitive {
	readonly id: string;
	/** The privilege context the primitive operates in (attacker) or fires in (victim). */
	readonly privilege: Privilege;
	readonly sideEffect: SideEffect;
	readonly vulnClass: string;
	/** Short, non-secret description. */
	readonly summary: string;
	/** Persistence store this primitive writes to / reads from — the bridge key. */
	readonly store?: string | undefined;
	/** Where attacker-controlled input enters (for the dataflow edge). */
	readonly source?: TaintPathStep | undefined;
	/** Where the effect lands (the write call, the render sink, …). */
	readonly sink?: TaintPathStep | undefined;
	/** Correlation back to a taint observation, when derived from one. */
	readonly taintObservationId?: string | undefined;
}

/**
 * A real dataflow edge between two primitives, derived from the CPG (a
 * second-order taint observation) or supplied explicitly. Its presence is the
 * composability proof: `from` is the producer's output, `to` the consumer's sink.
 */
export interface DataflowEdge {
	/** Provenance: the taint observation id this edge came from (audit trail). */
	readonly observationId: string;
	/** The shared persistence store, when the edge bridges one. */
	readonly store?: string | undefined;
	readonly from: TaintPathStep;
	readonly to: TaintPathStep;
}

/** One required step of a goal, matched to a ledger primitive by tag + privilege band. */
export interface GoalStep {
	readonly role: string;
	readonly sideEffect: SideEffect;
	/** Accepted privilege band for a matching primitive (inclusive; open if absent). */
	readonly minPrivilege?: Privilege;
	readonly maxPrivilege?: Privilege;
}

/** A high-impact end-state stated backward as the primitives that would achieve it. */
export interface Goal {
	readonly id: string;
	readonly name: string;
	readonly impact: "critical" | "high";
	/** Steps ordered producer→consumer; adjacent steps MUST compose to complete. */
	readonly steps: readonly GoalStep[];
}

/** One step aligned to the ledger primitive that satisfied it (if any). */
export interface StepMatch {
	readonly step: GoalStep;
	readonly primitive?: Primitive | undefined;
}

/** The proximity-ranked result of hunting one goal against the ledger. */
export interface GoalMatch {
	readonly goal: Goal;
	readonly matches: readonly StepMatch[];
	readonly matchedCount: number;
	/** steps.length - matchedCount; `1` ⇒ "one primitive away" (floats to the top). */
	readonly missingCount: number;
	/** All steps tag-matched. NOT proof — composability + dynamic proof still required. */
	readonly complete: boolean;
}

/** A tag-complete goal resolved to one primitive per step, in order. */
export interface CandidateChain {
	readonly goal: Goal;
	readonly primitives: readonly Primitive[];
}

/** One adjacency in a candidate chain and whether a real dataflow edge composes it. */
export interface CompositionLink {
	readonly from: Primitive;
	readonly to: Primitive;
	readonly composable: boolean;
	readonly edge?: DataflowEdge | undefined;
	/** Why the pair does NOT compose (present only when `composable` is false). */
	readonly reason?: string | undefined;
}

/** The result of the static composability check over a whole chain. */
export interface CompositionResult {
	readonly links: readonly CompositionLink[];
	/** True only when EVERY adjacent pair has a real dataflow edge. */
	readonly composable: boolean;
}

/** Outcome of the dynamic OOB confirmation (blind proof: fail-open, never refutes). */
export type ChainProofStatus = "confirmed" | "inconclusive";

export interface ChainProof {
	readonly status: ChainProofStatus;
	readonly detail: string;
	/** The tagged OOB callback host used (non-secret marker), for the audit trail. */
	readonly callbackHost?: string | undefined;
}

/** Final chain status. `confirmed` = composable AND dynamically proven. */
export type ChainStatus = "unproven" | "composable" | "confirmed" | "inconclusive";

export interface ChainVerdict {
	readonly goal: Goal;
	readonly status: ChainStatus;
	readonly composition: CompositionResult;
	readonly dynamic?: ChainProof | undefined;
	readonly reason: string;
}
