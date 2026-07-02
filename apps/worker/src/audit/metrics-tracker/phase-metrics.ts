// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { AGENT_PHASE_MAP, type PhaseName } from "../../session-manager.js";
import type { AgentName } from "../../types/index.js";
import { calculatePercentage } from "../../utils/formatting.js";
import type { AgentAuditMetrics, PhaseMetrics } from "./types.js";

/**
 * Calculate phase-level metrics from successful agents.
 *
 * @param successfulAgents - List of [agentName, metrics] tuples for agents whose status is 'success'
 * @param totalDuration - Sum of all successful agents' final_duration_ms; used for percentages
 */
export function calculatePhaseMetrics(
	successfulAgents: Array<[string, AgentAuditMetrics]>,
	totalDuration: number,
): Record<string, PhaseMetrics> {
	const phases: Record<PhaseName, AgentAuditMetrics[]> = {
		"pre-recon": [],
		recon: [],
		"threat-model": [],
		"vulnerability-analysis": [],
		"adversarial-screen": [],
		exploitation: [],
		oracle: [],
		reporting: [],
		"attack-surface": [],
	};

	// Group agents by phase using imported AGENT_PHASE_MAP
	for (const [agentName, agentData] of successfulAgents) {
		const phase = AGENT_PHASE_MAP[agentName as AgentName];
		if (phase) {
			phases[phase].push(agentData);
		}
	}

	// Calculate metrics per phase
	const phaseMetrics: Record<string, PhaseMetrics> = {};

	for (const [phaseName, agentList] of Object.entries(phases)) {
		if (agentList.length === 0) continue;

		const phaseDuration = agentList.reduce(
			(sum, agent) => sum + agent.final_duration_ms,
			0,
		);

		phaseMetrics[phaseName] = {
			duration_ms: phaseDuration,
			duration_percentage: calculatePercentage(phaseDuration, totalDuration),
			agent_count: agentList.length,
		};
	}

	return phaseMetrics;
}
