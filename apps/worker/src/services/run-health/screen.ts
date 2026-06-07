// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Screen-health summary: turn a category's `{category}_screen_verdicts.json` into
 * a fail-open census. The run analysis found 60–70% of voters "produced no
 * structured verdict (fail-open)" for some categories — validation that silently
 * did not happen. This makes that rate a first-class, loud signal, and separates
 * a BROKEN voter (fail-open) from a DELIBERATE "unreachable:" abstention so the
 * two are not conflated. Pure — no I/O.
 */

/** How a single voter ballot landed. */
export type VoteClass = "real" | "failopen" | "unreachable";

/**
 * Classify a ballot by its reason text:
 *  - `unreachable` — the voter deliberately abstained because the surface was
 *    not reachable (reason starts "unreachable:"); a targeting signal, not a bug.
 *  - `failopen` — the voter produced no parseable verdict and fell open; the
 *    validation check did not actually run.
 *  - `real` — a genuine verdict the voter reasoned to.
 */
export function classifyVote(reason: string): VoteClass {
	const r = reason.trim().toLowerCase();
	if (r.startsWith("unreachable:")) return "unreachable";
	if (r.includes("no structured verdict") || r.includes("fail-open")) {
		return "failopen";
	}
	return "real";
}

export interface CategoryScreenHealth {
	category: string;
	entries: number;
	totalVotes: number;
	real: number;
	failOpen: number;
	unreachable: number;
	/** failOpen / totalVotes (0 when no votes). */
	failOpenRate: number;
}

/** Summarize one category's verdicts array (unknown-shaped, defensively read). */
export function summarizeCategoryScreen(
	category: string,
	verdicts: unknown,
): CategoryScreenHealth {
	const entries = Array.isArray(verdicts) ? verdicts : [];
	let totalVotes = 0;
	let real = 0;
	let failOpen = 0;
	let unreachable = 0;
	for (const entry of entries) {
		const votes =
			entry !== null &&
			typeof entry === "object" &&
			Array.isArray((entry as { votes?: unknown }).votes)
				? (entry as { votes: unknown[] }).votes
				: [];
		for (const vote of votes) {
			totalVotes += 1;
			const reason =
				vote !== null &&
				typeof vote === "object" &&
				typeof (vote as { reason?: unknown }).reason === "string"
					? (vote as { reason: string }).reason
					: "";
			const cls = classifyVote(reason);
			if (cls === "real") real += 1;
			else if (cls === "failopen") failOpen += 1;
			else unreachable += 1;
		}
	}
	return {
		category,
		entries: entries.length,
		totalVotes,
		real,
		failOpen,
		unreachable,
		failOpenRate: totalVotes > 0 ? failOpen / totalVotes : 0,
	};
}
