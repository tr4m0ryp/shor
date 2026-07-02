// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Pure majority aggregation for the screen panel. No I/O, no SDK — just the
 * decision rule, so it is exhaustively unit-testable.
 */

import { REACHABILITY_LENS } from "./lenses.js";
import type { ScreenDecision, ScreenVerdictEntry, ScreenVote } from "./types.js";

/**
 * Decide one candidate from its voters' ballots.
 *
 * Rule:
 *  - Strict plurality wins: the verdict with strictly more votes than BOTH
 *    others becomes the decision.
 *  - Any tie or split (no strict plurality) collapses to `uncertain` — the panel
 *    is not confident, so the finding stays in (fail open), it is not dropped.
 *  - Reachability veto: a single reachability-lens `refute` forbids a `support`
 *    decision, downgrading it to `uncertain`. An unreachable sink cannot be
 *    confidently supported, but one lens does not get to `refute` (drop) on its
 *    own — only the conservative middle.
 *  - An empty ballot is `uncertain`.
 */
export function decideVotes(votes: readonly ScreenVote[]): ScreenDecision {
	if (votes.length === 0) return "uncertain";

	let refute = 0;
	let support = 0;
	let uncertain = 0;
	for (const v of votes) {
		if (v.verdict === "refute") refute += 1;
		else if (v.verdict === "support") support += 1;
		else uncertain += 1;
	}

	let decision: ScreenDecision;
	if (refute > support && refute > uncertain) decision = "refute";
	else if (support > refute && support > uncertain) decision = "support";
	else decision = "uncertain";

	if (
		decision === "support" &&
		votes.some(
			(v) => v.lens === REACHABILITY_LENS && v.verdict === "refute",
		)
	) {
		decision = "uncertain";
	}

	return decision;
}

/**
 * Assemble one verdict entry: the candidate id, its ballots (ordered by voter
 * ordinal for stable, diffable output), and the aggregated decision.
 */
export function buildVerdictEntry(
	id: string,
	votes: readonly ScreenVote[],
): ScreenVerdictEntry {
	const ordered = [...votes].sort((a, b) => a.voter - b.voter);
	return { id, votes: ordered, decision: decideVotes(ordered) };
}
