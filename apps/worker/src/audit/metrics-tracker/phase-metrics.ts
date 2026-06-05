// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
