// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Live progress emitter for the Cloud Run Job pipeline (ADR-051).
 *
 * As the pipeline walks its agents it POSTs a snapshot to the dashboard:
 *   POST `${SHOR_FINDINGS_SINK_URL}/scans/${SHOR_SCAN_ID}/progress`
 *   Authorization: Bearer ${SHOR_SINK_TOKEN}
 *   body: { status, currentPhase, currentAgent, failedAgent, completedAgents }
 *
 * This is the activity-feed counterpart to the terminal findings POST. The
 * dashboard polls a read route that blends these snapshots with the static
 * phase/agent plan. Best-effort: a missing sink config or a failed request is
 * swallowed (the Job's exit code is driven by the pipeline, never the feed). The
 * bearer token is never logged.
 */

import { AGENT_PHASE_MAP } from "../../session-manager.js";
import type { PhaseName } from "../../session-manager.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentName } from "../../types/agents.js";
import { readSinkConfig, type SinkConfig } from "../findings/sink.js";
import { buildCoverageMap, type CoverageSummary } from "./coverage-map.js";
import { skillTracker } from "./skill-tracker.js";

/**
 * Service phases that report progress but are NOT LLM agents — they have no
 * `AGENTS` entry and are absent from `ALL_AGENTS` (so they can't pollute the
 * agent registry / its exhaustive maps). The deterministic post-exploitation
 * oracle is one: it does real work (replays PoCs) but runs no agent, so without
 * a marker its phase card sits at "0/0 QUEUED" forever. Emitting under this key
 * lets the dashboard render it running/done like any other phase.
 */
export type ServicePhaseAgent = "oracle";

/** Any progress key: a real agent, or a non-agent service-phase marker. */
type ProgressAgent = AgentName | ServicePhaseAgent;

/** Resolve the phase for any progress key (service markers map to their own phase). */
function phaseOf(agent: ProgressAgent): PhaseName {
	return agent === "oracle" ? "oracle" : AGENT_PHASE_MAP[agent];
}

interface AgentProgress {
	agent: string;
	status: "completed" | "failed";
	durationMs: number;
	/** Epoch ms — drives the run timeline (Gantt). */
	startedAt: number;
	finishedAt: number;
}

interface ProgressSnapshot {
	status: "running";
	currentPhase: string | null;
	currentAgent: string | null;
	failedAgent: string | null;
	/** All agents running RIGHT NOW (≥1 under concurrency). */
	runningAgents: string[];
	completedAgents: AgentProgress[];
	/** agent → epoch-ms it started (covers still-running agents for the timeline). */
	starts: Record<string, number>;
	/** agent → skills it has used so far (live, from the skill tracker). */
	skills: Record<string, string[]>;
	/**
	 * Per-agent coverage summary (ran / missing / floor), computed at emit time
	 * from Task 001's evaluateCoverage. Optional for backward compatibility with
	 * older dashboard versions that do not yet render coverage.
	 */
	coverage?: Record<string, CoverageSummary>;
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
	private readonly running = new Set<AgentName>();
	private readonly starts: Record<string, number> = {};
	private lastFailed: AgentName | null = null;
	private lastSkillEmit = 0;

	constructor(
		scanId: string,
		private readonly logger: ActivityLogger,
	) {
		this.config = readSinkConfig(scanId);
		// Push a live update the first time any running agent reaches for a new
		// skill, throttled so a burst of tool calls is one post every ~3s.
		skillTracker.onNewSkill = () => {
			const now = Date.now();
			if (now - this.lastSkillEmit < 3000) return;
			this.lastSkillEmit = now;
			void this.emit();
		};
	}

	/** A representative running agent for the banner (last started). */
	private representative(): AgentName | null {
		let rep: AgentName | null = null;
		for (const a of this.running) rep = a;
		return rep;
	}

	private async emit(): Promise<void> {
		if (!this.config) return;
		const rep = this.representative();
		const skills = skillTracker.all();
		await post(
			this.config,
			{
				status: "running",
				currentPhase: rep ? AGENT_PHASE_MAP[rep] : null,
				currentAgent: rep,
				failedAgent: this.lastFailed,
				runningAgents: [...this.running],
				completedAgents: this.completed,
				starts: this.starts,
				skills,
				coverage: buildCoverageMap(skills),
			},
			this.logger,
		);
	}

	/** Announce an agent is now running (≥1 may run concurrently). */
	async started(agent: AgentName): Promise<void> {
		this.running.add(agent);
		this.starts[agent] = Date.now();
		await this.emit();
	}

	/** Record an agent finished successfully and push the updated snapshot. */
	async completed_(agent: AgentName, durationMs: number): Promise<void> {
		this.running.delete(agent);
		const startedAt = this.starts[agent] ?? Date.now() - durationMs;
		this.completed.push({ agent, status: "completed", durationMs, startedAt, finishedAt: Date.now() });
		await this.emit();
	}

	/** Record an agent failed; the terminal status is set by the findings POST. */
	async failed(agent: AgentName, durationMs: number): Promise<void> {
		this.running.delete(agent);
		this.lastFailed = agent;
		const startedAt = this.starts[agent] ?? Date.now() - durationMs;
		this.completed.push({ agent, status: "failed", durationMs, startedAt, finishedAt: Date.now() });
		await this.emit();
	}
}
