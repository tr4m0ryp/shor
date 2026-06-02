// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Live progress emitter for the Cloud Run Job pipeline (ADR-051).
 *
 * As the pipeline walks its agents it POSTs a snapshot to the dashboard:
 *   POST `${AEGIS_FINDINGS_SINK_URL}/scans/${AEGIS_SCAN_ID}/progress`
 *   Authorization: Bearer ${AEGIS_SINK_TOKEN}
 *   body: { status, currentPhase, currentAgent, failedAgent, completedAgents }
 *
 * This is the activity-feed counterpart to the terminal findings POST. The
 * dashboard polls a read route that blends these snapshots with the static
 * phase/agent plan. Best-effort: a missing sink config or a failed request is
 * swallowed (the Job's exit code is driven by the pipeline, never the feed). The
 * bearer token is never logged.
 */

import { AGENT_PHASE_MAP } from "../../session-manager.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentName } from "../../types/agents.js";
import { readSinkConfig, type SinkConfig } from "../findings/sink.js";
import { skillTracker } from "./skill-tracker.js";

interface AgentProgress {
	agent: string;
	status: "completed" | "failed";
	durationMs: number;
}

interface ProgressSnapshot {
	status: "running";
	currentPhase: string | null;
	currentAgent: string | null;
	failedAgent: string | null;
	completedAgents: AgentProgress[];
	/** agent → skills it has used so far (live, from the skill tracker). */
	skills: Record<string, string[]>;
}

async function post(config: SinkConfig, snapshot: ProgressSnapshot, logger: ActivityLogger): Promise<void> {
	const url = `${config.baseUrl}/scans/${encodeURIComponent(config.scanId)}/progress`;
	try {
		const res = await fetch(url, {
			method: "POST",
			headers: { "content-type": "application/json", authorization: `Bearer ${config.token}` },
			body: JSON.stringify(snapshot),
		});
		if (!res.ok) {
			logger.warn?.("Progress sink returned non-2xx", { scanId: config.scanId, httpStatus: res.status });
		}
	} catch (err) {
		logger.warn?.("Failed to POST progress to sink", {
			scanId: config.scanId,
			error: err instanceof Error ? err.message : String(err),
		});
	}
}

/**
 * Stateful emitter: tracks completed agents across the run so each snapshot is
 * cumulative. Construct once per pipeline; call `started`/`completed`/`failed`
 * around each agent. A no-op when the sink is not configured.
 */
export class ProgressEmitter {
	private readonly config: SinkConfig | undefined;
	private readonly completed: AgentProgress[] = [];
	private current: AgentName | null = null;
	private lastSkillEmit = 0;

	constructor(
		scanId: string,
		private readonly logger: ActivityLogger,
	) {
		this.config = readSinkConfig(scanId);
		// Push a live update the first time a running agent reaches for a new
		// skill, throttled so a burst of tool calls is one post every ~3s.
		skillTracker.onNewSkill = () => {
			const now = Date.now();
			if (now - this.lastSkillEmit < 3000) return;
			this.lastSkillEmit = now;
			void this.emit(this.current, this.current, null);
		};
	}

	private async emit(
		phaseAgent: AgentName | null,
		currentAgent: AgentName | null,
		failedAgent: AgentName | null,
	): Promise<void> {
		if (!this.config) return;
		await post(
			this.config,
			{
				status: "running",
				currentPhase: phaseAgent ? AGENT_PHASE_MAP[phaseAgent] : null,
				currentAgent,
				failedAgent,
				completedAgents: this.completed,
				skills: skillTracker.all(),
			},
			this.logger,
		);
	}

	/** Announce an agent is now running (current phase derived from the agent). */
	async started(agent: AgentName): Promise<void> {
		this.current = agent;
		skillTracker.setAgent(agent);
		await this.emit(agent, agent, null);
	}

	/** Record an agent finished successfully and push the updated snapshot. */
	async completed_(agent: AgentName, durationMs: number): Promise<void> {
		this.completed.push({ agent, status: "completed", durationMs });
		this.current = null;
		await this.emit(agent, null, null);
	}

	/** Record an agent failed; the terminal status is set by the findings POST. */
	async failed(agent: AgentName, durationMs: number): Promise<void> {
		this.completed.push({ agent, status: "failed", durationMs });
		this.current = null;
		await this.emit(agent, null, agent);
	}
}
