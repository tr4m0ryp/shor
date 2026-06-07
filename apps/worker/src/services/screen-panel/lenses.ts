// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Panel configuration: the diverse-lens map, panel size, and per-voter session
 * assignment. Kept parallel to `prompt-manager/skill-recommendations.RECOMMENDED`
 * (a category/agent-keyed map of soft-scoping hints) so the two read the same.
 */

/**
 * The lens label that gates reachability. A reachability-lens `refute` can veto
 * a `support` majority (an unreachable sink cannot be confidently supported);
 * `aggregate.decideVotes` reads this constant.
 */
export const REACHABILITY_LENS = "reachability";

/**
 * The base lens triad applied to every category. Each voter judges its candidate
 * primarily through one lens, so the panel's N ballots are diverse rather than N
 * copies of one skeptic.
 */
const BASE_LENSES = ["reachability", "control-sanitizer", "exploitability"] as const;

/**
 * Per-category lens pool (parallel to `RECOMMENDED`). Authorization screens get a
 * fourth identity/role lens because a broken-access claim only holds under a real
 * identity boundary. Categories absent here fall back to {@link BASE_LENSES}.
 */
export const LENSES: Readonly<Record<string, readonly string[]>> = {
	injection: BASE_LENSES,
	xss: BASE_LENSES,
	auth: BASE_LENSES,
	ssrf: BASE_LENSES,
	authz: [...BASE_LENSES, "auth-context"],
	logic: BASE_LENSES,
	"misconfig-web": BASE_LENSES,
};

/** Default voters per candidate panel. */
export const DEFAULT_VOTERS = 3;
/** Hard ceiling on panel size (config can raise N up to here). */
export const MAX_VOTERS = 5;
/** Env var that overrides the panel size, clamped to `[1, MAX_VOTERS]`. */
export const VOTERS_ENV = "SHOR_SCREEN_VOTERS";

/**
 * Resolve the panel size N. Defaults to {@link DEFAULT_VOTERS} (3); a valid
 * `SHOR_SCREEN_VOTERS` overrides it, clamped to `[1, MAX_VOTERS]` (5). Any
 * malformed value falls back to the default rather than failing the scan.
 */
export function resolvePanelSize(env: NodeJS.ProcessEnv = process.env): number {
	const raw = env[VOTERS_ENV];
	if (raw === undefined || raw.trim() === "") return DEFAULT_VOTERS;
	const parsed = Number.parseInt(raw, 10);
	if (!Number.isFinite(parsed) || parsed < 1) return DEFAULT_VOTERS;
	return Math.min(parsed, MAX_VOTERS);
}

/**
 * The N lens labels for a category's panel. Cycles the category pool when N
 * exceeds its length (e.g. N=5 over a 3-lens pool repeats lenses — voters stay
 * independent via distinct ordinals/sessions even when a lens recurs).
 */
export function lensesForCategory(category: string, n: number): string[] {
	const pool = LENSES[category] ?? BASE_LENSES;
	const out: string[] = [];
	for (let i = 0; i < n && pool.length > 0; i++) {
		const lens = pool[i % pool.length];
		if (lens !== undefined) out.push(lens);
	}
	return out;
}

/** The fixed pool of isolated Playwright sessions. */
const SESSIONS: readonly PlaywrightSession[] = [
	"agent1",
	"agent2",
	"agent3",
	"agent4",
	"agent5",
];

/**
 * The distinct Playwright session for a 1-based voter ordinal. Within one panel
 * the voters span agent1..agentN, so concurrently-running voters never share a
 * browser context (independence). Panels run one candidate at a time, so the
 * pool is never oversubscribed.
 */
export function sessionForVoter(voter: number): PlaywrightSession {
	const idx = (voter - 1) % SESSIONS.length;
	return SESSIONS[idx] ?? "agent1";
}
