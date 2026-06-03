// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Pure helper: convert a skillTracker.all() map into a per-agent coverage
 * summary by calling evaluateCoverage once per agent.
 *
 * Extracted as a side-effect-free function so it can be unit-tested without
 * standing up a real ProgressEmitter or network sink.
 */

import { evaluateCoverage } from "../../services/coverage/evaluate.js";
import type { CoverageResult } from "../../services/coverage/types.js";
import type { AgentName } from "../../types/agents.js";

/** The slice of CoverageResult surfaced in the progress snapshot. */
export interface CoverageSummary {
	ran: string[];
	missing: string[];
	floor: number;
}

/**
 * Build an agent → coverage-summary map from the live skill map.
 *
 * Keys that are not valid AgentName values are silently skipped (defensive
 * against future tracker changes). Agents whose policy returns floor === 0
 * (synthesis agents like "report") are included; they are cheap to compute
 * and the dashboard can decide whether to render them.
 */
export function buildCoverageMap(
	agentSkills: Record<string, string[]>,
): Record<string, CoverageSummary> {
	const out: Record<string, CoverageSummary> = {};
	for (const agentKey of Object.keys(agentSkills)) {
		const result: CoverageResult = evaluateCoverage(agentKey as AgentName);
		out[agentKey] = {
			ran: result.ran,
			missing: result.missing,
			floor: result.floor,
		};
	}
	return out;
}
