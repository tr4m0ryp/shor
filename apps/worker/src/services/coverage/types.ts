// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Shared shapes for the agent skill-coverage evaluator.
 *
 * A `CoveragePolicy` describes the breadth we expect from one agent: the pool
 * of tools that "count" toward coverage (`candidates`), any tools that MUST be
 * exercised (`required` — empty for every agent by default), and the minimum
 * number of distinct candidate tools an agent should touch (`minCount`).
 *
 * `evaluateCoverage` reads what an agent actually ran (from `skillTracker`) and
 * returns a `CoverageResult` the downstream gate consumes.
 */

/** Per-agent breadth expectation. `candidates` is derived from `RECOMMENDED`. */
export interface CoveragePolicy {
	/** Tools that count toward coverage (the agent's recommended skill set). */
	readonly candidates: readonly string[];
	/** Tools that MUST run; their absence is a hard miss. Default: `[]`. */
	readonly required: readonly string[];
	/** Minimum number of distinct candidate tools the agent should exercise. */
	readonly minCount: number;
}

/**
 * Structured record of a run that proceeded BELOW its breadth floor (T4).
 *
 * The discovery loop is accept-and-proceed: a below-floor agent still continues
 * (see `runWithCoverage`), it only logs "still below floor … proceeding". This
 * object elevates that log line into a machine-readable signal carried on the
 * `CoverageResult` so the progress/findings layer can surface a below-floor run
 * to the dashboard instead of burying it in logs. Pure observability — its
 * presence changes no control flow.
 */
export interface CoverageShortfall {
	/** Always `true`: this object exists only when the floor was not met. */
	readonly belowFloor: true;
	/** Distinct candidate tools the agent actually exercised. */
	readonly ranTools: number;
	/** The `minCount` breadth floor the run fell short of. */
	readonly requiredFloor: number;
	/** Candidate tools the agent did NOT exercise. */
	readonly missing: string[];
}

/** Outcome of comparing an agent's actual tool usage against its policy. */
export interface CoverageResult {
	/** True when `ran.length >= floor` and there are no hard misses. */
	readonly ok: boolean;
	/** Candidate tools the agent actually exercised. */
	readonly ran: string[];
	/** Candidate tools the agent did NOT exercise (soft gap). */
	readonly missing: string[];
	/** `required` tools the agent did NOT exercise (hard gap). */
	readonly hardMissing: string[];
	/** The `minCount` floor this result was judged against. */
	readonly floor: number;
	/**
	 * Present ONLY when this result is below its floor (`ok === false`); absent
	 * when the floor is met. Mirrors the "below floor … proceeding" decision so a
	 * below-floor run is visible in the coverage artifact, not just in logs.
	 */
	readonly shortfall?: CoverageShortfall;
}
