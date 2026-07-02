// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Pure helper: convert a skillTracker.all() map into a per-agent coverage
 * summary by calling evaluateCoverage once per agent.
 *
 * Extracted as a side-effect-free function so it can be unit-tested without
 * standing up a real ProgressEmitter or network sink.
 */

import { evaluateCoverage } from "../../services/coverage/evaluate.js";
import type {
	CoverageResult,
	CoverageShortfall,
} from "../../services/coverage/types.js";
import type { AgentName } from "../../types/agents.js";

/** The slice of CoverageResult surfaced in the progress snapshot. */
export interface CoverageSummary {
	ran: string[];
	missing: string[];
	floor: number;
	/**
	 * Present ONLY for an agent that proceeded BELOW its breadth floor (T4): the
	 * structured "still below floor … proceeding" signal, surfaced so the
	 * dashboard can flag a below-floor run instead of it living only in logs.
	 * Absent when the floor was met (backward compatible — older dashboards
	 * simply ignore the field).
	 */
	shortfall?: CoverageShortfall;
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
			// Carry the below-floor shortfall through to the artifact only when set
			// (mirrors the optional `coverage` field's backward-compatible shape).
			...(result.shortfall !== undefined && { shortfall: result.shortfall }),
		};
	}
	return out;
}
