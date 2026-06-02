// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * In-process phased pipeline runner for the Cloud Run Job entrypoint (ADR-051).
 *
 * The inverted worker model drops per-scan `bundleWorkflowCode` and the self-
 * submitting Temporal worker: the Job runs the pipeline directly, driving each
 * agent through the same service layer the Temporal activities use
 * (`Container.agentExecution`). Agents run in canonical order; each gets its own
 * `AuditSession` (per-agent instance state cannot be shared).
 */

import { AuditSession } from "../audit/index.js";
import { deliverablesDir } from "../paths.js";
import { getOrCreateContainer } from "../services/container.js";
import { AGENTS } from "../session-manager.js";
import { ALL_AGENTS, type AgentName } from "../types/agents.js";
import type { ActivityLogger } from "../types/activity-logger.js";
import type { SessionMetadata } from "../types/audit.js";
import type { ScanJobParams } from "./env.js";
import { reportFindings } from "./findings/index.js";
import { ProgressEmitter } from "./progress/index.js";

/** Canonical agent execution order (pre-recon → … → attack-surface). */
const PIPELINE_AGENTS: readonly AgentName[] = ALL_AGENTS;

/** Per-agent metrics summary returned to the entrypoint. */
export interface AgentRunSummary {
	agent: AgentName;
	durationMs: number;
}

/** Outcome of one scan pipeline run. */
export interface PipelineRunResult {
	scanId: string;
	completedAgents: AgentRunSummary[];
}

/**
 * Run the full agent pipeline for one scan in-process. Throws on the first agent
 * failure so the Job exits non-zero (Temporal's activity surfaces the failure to
 * the workflow). Returns the per-agent metrics on success.
 */
export async function runScanPipeline(
	params: ScanJobParams,
	logger: ActivityLogger,
): Promise<PipelineRunResult> {
	const sessionMetadata: SessionMetadata = {
		id: params.scanId,
		webUrl: params.targetUrl,
		repoPath: params.repoPath,
	};

	const container = getOrCreateContainer(params.scanId, sessionMetadata);
	const deliverablesPath = deliverablesDir(
		params.repoPath,
		container.config.deliverablesSubdir,
	);

	const completedAgents: AgentRunSummary[] = [];
	const progress = new ProgressEmitter(params.scanId, logger);

	for (const agentName of PIPELINE_AGENTS) {
		const phase = AGENTS[agentName].displayName;
		logger.info(`Starting agent ${agentName}`, { phase, scanId: params.scanId });
		await progress.started(agentName);

		const auditSession = new AuditSession(sessionMetadata);
		await auditSession.initialize(params.scanId);

		const started = Date.now();
		let endResult: Awaited<ReturnType<typeof container.agentExecution.executeOrThrow>>;
		try {
			endResult = await container.agentExecution.executeOrThrow(
				agentName,
				{
					webUrl: params.targetUrl,
					repoPath: params.repoPath,
					deliverablesPath,
					attemptNumber: 1,
					...(params.configPath !== undefined && { configPath: params.configPath }),
				},
				auditSession,
				logger,
				container,
			);
		} catch (err) {
			// Mark this agent failed in the live feed before the Job exits non-zero.
			await progress.failed(agentName, Date.now() - started);
			throw err;
		}

		const durationMs = endResult.duration_ms || Date.now() - started;
		completedAgents.push({ agent: agentName, durationMs });
		await progress.completed_(agentName, durationMs);
		logger.info(`Completed agent ${agentName}`, { durationMs });

		// Incrementally push cumulative findings (status stays `running`) so a
		// timeout/OOM kill never loses a run's results — the dashboard already
		// has everything found up to the last completed agent.
		await reportFindings(deliverablesPath, params.scanId, "running", logger);
	}

	return { scanId: params.scanId, completedAgents };
}
