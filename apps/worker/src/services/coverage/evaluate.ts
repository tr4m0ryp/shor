// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Pure coverage evaluator.
 *
 * `evaluateCoverage(agent)` compares the tools an agent actually exercised
 * (read from `skillTracker` by agentName) against its `COVERAGE_POLICY`, with
 * the candidate pool derived from `RECOMMENDED[promptForAgent(agent)]`.
 *
 * Agents with no policy (report, attack-surface) short-circuit to `ok: true` —
 * synthesis agents run no offensive tools, so there is nothing to cover.
 *
 * The skill reader is injectable (defaulting to the process-scoped singleton)
 * purely so unit tests can supply a deterministic stub; production callers use
 * the one-argument form.
 */

import { skillTracker } from "../../job/progress/skill-tracker.js";
import type { AgentName } from "../../types/agents.js";
import { RECOMMENDED } from "../prompt-manager/skill-recommendations.js";
import { COVERAGE_POLICY } from "./policy.js";
import { promptForAgent } from "./reconcile.js";
import type { CoveragePolicy, CoverageResult } from "./types.js";

/** Reads the distinct skills an agent has exercised, keyed by agentName. */
export type SkillReader = (agent: AgentName) => readonly string[];

const defaultReader: SkillReader = (agent) => skillTracker.skillsFor(agent);

/** Candidate tools for an agent: its recommended skill set, or `[]`. */
function candidatesFor(agent: AgentName): readonly string[] {
	return RECOMMENDED[promptForAgent(agent)] ?? [];
}

/**
 * The full, composed policy for an agent (candidates derived from
 * `RECOMMENDED`), or `undefined` when the agent has no coverage expectation.
 */
export function policyFor(agent: AgentName): CoveragePolicy | undefined {
	const thresholds = COVERAGE_POLICY[agent];
	if (!thresholds) return undefined;
	return {
		candidates: candidatesFor(agent),
		required: thresholds.required,
		minCount: thresholds.minCount,
	};
}

/**
 * Judge one agent's tool breadth against its policy.
 *
 * - `ran`         = candidates the agent actually exercised
 * - `missing`     = candidates it did NOT exercise (soft gap)
 * - `hardMissing` = `required` tools it did NOT exercise (hard gap)
 * - `ok`          = `ran.length >= minCount` AND `hardMissing` is empty
 * - `shortfall`   = a structured below-floor record, set ONLY when `ok` is false
 *   (the accept-and-proceed signal the coverage artifact surfaces); absent
 *   otherwise.
 *
 * No policy → `{ ok: true, ran: [], missing: [], hardMissing: [], floor: 0 }`.
 */
export function evaluateCoverage(
	agent: AgentName,
	reader: SkillReader = defaultReader,
): CoverageResult {
	const policy = policyFor(agent);
	if (!policy) {
		return { ok: true, ran: [], missing: [], hardMissing: [], floor: 0 };
	}

	const used = new Set(reader(agent));
	const ran = policy.candidates.filter((tool) => used.has(tool));
	const missing = policy.candidates.filter((tool) => !used.has(tool));
	const hardMissing = policy.required.filter((tool) => !used.has(tool));
	const ok = ran.length >= policy.minCount && hardMissing.length === 0;

	const base: CoverageResult = {
		ok,
		ran,
		missing,
		hardMissing,
		floor: policy.minCount,
	};
	// Accept-and-proceed: below floor we do NOT block; we only attach a
	// structured shortfall so the run is visible in the coverage artifact.
	if (ok) return base;
	return {
		...base,
		shortfall: {
			belowFloor: true,
			ranTools: ran.length,
			requiredFloor: policy.minCount,
			missing,
		},
	};
}
