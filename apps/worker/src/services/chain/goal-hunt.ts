// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Proximity-ranked goal hunt (spec T11, F8) — the "gem" of Ali's design, kept
 * (and its fatal completeness gap deferred to composability).
 *
 * High-value end-states are stated BACKWARD as the primitives that would achieve
 * them. Each goal step is greedily matched to a ledger primitive by side-effect +
 * privilege band. Goals are ranked by PROXIMITY — how few primitives are missing —
 * so "one primitive away from a critical chain" floats to the top, inverting
 * bottom-up sink enumeration. `nextHunt` turns the closest incomplete goal into a
 * concrete directive: which primitive to go look for next.
 *
 * A tag-`complete` GoalMatch is NOT a proven chain — it only means every step
 * found a type-compatible primitive. Composability (a real dataflow edge) and
 * dynamic proof are required before a chain is declared complete (see
 * `composability.ts`). Pure + deterministic over the ledger.
 */

import type { PrimitiveLedger } from "./ledger.js";
import type { CandidateChain, Goal, GoalMatch, GoalStep, Primitive, StepMatch } from "./types.js";
import { withinBand } from "./types.js";

/**
 * Built-in high-impact goals (general-web, no WordPress-specific chains). Steps
 * are ordered producer→consumer so composability can walk adjacent pairs.
 */
export const DEFAULT_GOALS: readonly Goal[] = [
	{
		id: "stored_xss_to_privileged_session",
		name: "Stored XSS rendered in a privileged session (account/privilege takeover)",
		impact: "critical",
		steps: [
			// A low-priv (or anon) actor persists a payload…
			{ role: "store_payload", sideEffect: "state_write", minPrivilege: "unauth", maxPrivilege: "low_priv" },
			// …that is later rendered into a high-priv victim's session.
			{ role: "render_to_privileged_victim", sideEffect: "render", minPrivilege: "high_priv", maxPrivilege: "admin" },
		],
	},
	{
		id: "idor_write_to_auth_takeover",
		name: "Cross-user write escalated to an auth-state change (account takeover)",
		impact: "critical",
		steps: [
			{ role: "cross_user_write", sideEffect: "state_write", minPrivilege: "low_priv", maxPrivilege: "cross_user" },
			{ role: "auth_state_change", sideEffect: "auth_transition", minPrivilege: "cross_user", maxPrivilege: "admin" },
		],
	},
	{
		id: "stored_ssrf_pivot",
		name: "Stored attacker input reaches a server-side fetch (SSRF pivot)",
		impact: "high",
		steps: [
			{ role: "store_url", sideEffect: "state_write", minPrivilege: "unauth", maxPrivilege: "low_priv" },
			{ role: "server_side_fetch", sideEffect: "redirect", minPrivilege: "self", maxPrivilege: "admin" },
		],
	},
];

/** Does a primitive satisfy a step (side-effect tag + privilege band)? */
function stepMatches(step: GoalStep, primitive: Primitive): boolean {
	return (
		primitive.sideEffect === step.sideEffect &&
		withinBand(primitive.privilege, step.minPrivilege, step.maxPrivilege)
	);
}

/**
 * Greedily align each goal step to a distinct ledger primitive. A primitive is
 * consumed by the first step it satisfies (so two steps never claim the same
 * finding). Returns the per-step alignment plus proximity counts.
 */
export function huntGoal(goal: Goal, ledger: PrimitiveLedger): GoalMatch {
	const used = new Set<string>();
	const matches: StepMatch[] = [];
	let matchedCount = 0;
	for (const step of goal.steps) {
		const found = ledger.find((p) => !used.has(p.id) && stepMatches(step, p))[0];
		if (found) {
			used.add(found.id);
			matchedCount += 1;
			matches.push({ step, primitive: found });
		} else {
			matches.push({ step });
		}
	}
	return {
		goal,
		matches,
		matchedCount,
		missingCount: goal.steps.length - matchedCount,
		complete: matchedCount === goal.steps.length,
	};
}

/** Impact ordering for the rank tie-break (critical outranks high). */
const IMPACT_RANK: Record<Goal["impact"], number> = { critical: 0, high: 1 };

/**
 * Hunt every goal and rank by PROXIMITY: fewest missing primitives first, then
 * impact, then most matched. A goal one primitive away from critical thus sorts
 * above a goal missing several — the goal-directed inversion.
 */
export function huntGoals(
	goals: readonly Goal[],
	ledger: PrimitiveLedger,
): GoalMatch[] {
	return goals
		.map((g) => huntGoal(g, ledger))
		.sort(
			(a, b) =>
				a.missingCount - b.missingCount ||
				IMPACT_RANK[a.goal.impact] - IMPACT_RANK[b.goal.impact] ||
				b.matchedCount - a.matchedCount,
		);
}

/** A directive for what to hunt next: the closest incomplete goal's first gap. */
export interface HuntDirective {
	readonly goal: Goal;
	readonly missingStep: GoalStep;
	readonly missingCount: number;
}

/**
 * The next thing worth hunting: from the proximity-ranked matches, the first
 * unmatched step of the closest incomplete goal. Returns undefined when every
 * goal is either complete or unmatchable (nothing actionable left).
 */
export function nextHunt(matches: readonly GoalMatch[]): HuntDirective | undefined {
	for (const m of matches) {
		if (m.missingCount === 0) continue; // already tag-complete
		const gap = m.matches.find((sm) => !sm.primitive);
		if (gap) return { goal: m.goal, missingStep: gap.step, missingCount: m.missingCount };
	}
	return undefined;
}

/**
 * Turn a tag-complete GoalMatch into a {@link CandidateChain} (one primitive per
 * step, in order). Returns undefined for an incomplete match — a chain candidate
 * requires every step filled BEFORE composability is even attempted.
 */
export function toCandidateChain(match: GoalMatch): CandidateChain | undefined {
	if (!match.complete) return undefined;
	const primitives: Primitive[] = [];
	for (const sm of match.matches) {
		if (!sm.primitive) return undefined; // defensive: complete ⇒ all present
		primitives.push(sm.primitive);
	}
	return { goal: match.goal, primitives };
}
