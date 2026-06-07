// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * N-vote diverse-lens screen panel (spec T8 + T11).
 *
 * Public surface: the pipeline calls {@link runScreenPanel} in place of the
 * single screen agent per category. The panel runs N independent lens-voters per
 * candidate, aggregates by majority, and writes `{category}_screen_verdicts.json`
 * (the stable artifact task 012's `applyScreenVerdicts` consumes).
 */

export { buildVerdictEntry, decideVotes } from "./aggregate.js";
export {
	DEFAULT_VOTERS,
	LENSES,
	lensesForCategory,
	MAX_VOTERS,
	panelSizeForCategory,
	REACHABILITY_LENS,
	resolvePanelSize,
	VOTERS_ENV,
} from "./lenses.js";
export { runScreenPanel } from "./runner.js";
export {
	createSessionPool,
	SCREEN_SESSIONS,
	type SessionLease,
	type SessionPool,
} from "./session-pool.js";
export type {
	ScreenDecision,
	ScreenVerdictEntry,
	ScreenVote,
} from "./types.js";
export { runVoter, voterFramingBlock } from "./voter.js";
