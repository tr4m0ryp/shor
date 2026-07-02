// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Metrics Tracker
 *
 * Manages session.json with comprehensive timing and validation metrics.
 * Tracks attempt-level data for complete forensic trail.
 */

import { PentestError } from "../../services/error-handling.js";
import { ErrorCode } from "../../types/errors.js";
import type { AgentEndResult } from "../../types/index.js";
import { atomicWrite, fileExists, readJson } from "../../utils/file-io.js";
import { formatTimestamp } from "../../utils/formatting.js";
import { generateSessionJsonPath, type SessionMetadata } from "../utils.js";
import { calculatePhaseMetrics } from "./phase-metrics.js";
import type {
	ActiveTimer,
	AttemptData,
	ResumeAttempt,
	SessionData,
} from "./types.js";

/** MetricsTracker - Manages metrics for a session. */
export class MetricsTracker {
	private sessionMetadata: SessionMetadata;
	private sessionJsonPath: string;
	private data: SessionData | null = null;
	private activeTimers: Map<string, ActiveTimer> = new Map();

	constructor(sessionMetadata: SessionMetadata) {
		this.sessionMetadata = sessionMetadata;
		this.sessionJsonPath = generateSessionJsonPath(sessionMetadata);
	}

	/**
	 * Initialize session.json (idempotent).
	 *
	 * @param workflowId - Optional workflow ID to set as originalWorkflowId for new sessions
	 */
	async initialize(workflowId?: string): Promise<void> {
		const exists = await fileExists(this.sessionJsonPath);

		if (exists) {
			this.data = await readJson<SessionData>(this.sessionJsonPath);
		} else {
			this.data = this.createInitialData(workflowId);
			await this.save();
		}
	}

	/** Create initial session.json structure. */
	private createInitialData(workflowId?: string): SessionData {
		const sessionData: SessionData = {
			session: {
				id: this.sessionMetadata.id,
				webUrl: this.sessionMetadata.webUrl,
				status: "in-progress",
				createdAt:
					(this.sessionMetadata as { createdAt?: string }).createdAt ||
					formatTimestamp(),
				resumeAttempts: [],
			},
			metrics: {
				total_duration_ms: 0,
				phases: {}, // Phase-level aggregations
				agents: {}, // Agent-level metrics
			},
		};

		if (workflowId) {
			sessionData.session.originalWorkflowId = workflowId;
		}

		if (this.sessionMetadata.repoPath) {
			sessionData.session.repoPath = this.sessionMetadata.repoPath;
		}
		return sessionData;
	}

	/** Start tracking an agent execution. */
	startAgent(agentName: string, attemptNumber: number): void {
		this.activeTimers.set(agentName, {
			startTime: Date.now(),
			attemptNumber,
		});
	}

	/** End agent execution and update metrics. */
	async endAgent(agentName: string, result: AgentEndResult): Promise<void> {
		if (!this.data) {
			throw new PentestError(
				"MetricsTracker not initialized",
				"validation",
				false,
				{},
				ErrorCode.AGENT_EXECUTION_FAILED,
			);
		}

		// 1. Initialize agent metrics if first time seeing this agent
		const existingAgent = this.data.metrics.agents[agentName];
		const agent = existingAgent ?? {
			status: "in-progress" as const,
			attempts: [],
			final_duration_ms: 0,
		};
		this.data.metrics.agents[agentName] = agent;

		// 2. Build attempt record with optional model/error fields
		const attempt: AttemptData = {
			attempt_number: result.attemptNumber,
			duration_ms: result.duration_ms,
			success: result.success,
			timestamp: formatTimestamp(),
		};

		if (result.model) {
			attempt.model = result.model;
		}

		if (result.error) {
			attempt.error = result.error;
		}

		// 3. Append attempt to history
		agent.attempts.push(attempt);

		// 4. Update agent status based on outcome
		if (result.success) {
			agent.status = "success";
			agent.final_duration_ms = result.duration_ms;

			// 5. Attach model and checkpoint metadata on success
			if (result.model) {
				agent.model = result.model;
			}

			if (result.checkpoint) {
				agent.checkpoint = result.checkpoint;
			}
		} else {
			if (result.isFinalAttempt) {
				agent.status = "failed";
			}
		}

		// 6. Clear active timer
		this.activeTimers.delete(agentName);

		// 7. Recalculate phase and session-level aggregations
		this.recalculateAggregations();

		// 8. Persist to session.json
		await this.save();
	}

	/** Update session status. */
	async updateSessionStatus(
		status: "in-progress" | "completed" | "failed" | "cancelled",
	): Promise<void> {
		if (!this.data) return;

		this.data.session.status = status;

		if (
			status === "completed" ||
			status === "failed" ||
			status === "cancelled"
		) {
			this.data.session.completedAt = formatTimestamp();
		}

		await this.save();
	}

	/**
	 * Add a resume attempt to the session.
	 *
	 * @param workflowId - The new workflow ID for this resume attempt
	 * @param terminatedWorkflows - IDs of workflows that were terminated
	 * @param checkpointHash - Git checkpoint hash that was restored
	 */
	async addResumeAttempt(
		workflowId: string,
		terminatedWorkflows: string[],
		checkpointHash?: string,
	): Promise<void> {
		if (!this.data) {
			throw new PentestError(
				"MetricsTracker not initialized",
				"validation",
				false,
				{},
				ErrorCode.AGENT_EXECUTION_FAILED,
			);
		}

		// Ensure originalWorkflowId is set (backfill if missing from old sessions)
		if (!this.data.session.originalWorkflowId) {
			this.data.session.originalWorkflowId = this.data.session.id;
		}

		// Ensure resumeAttempts array exists
		if (!this.data.session.resumeAttempts) {
			this.data.session.resumeAttempts = [];
		}

		// Add new resume attempt
		const resumeAttempt: ResumeAttempt = {
			workflowId,
			timestamp: formatTimestamp(),
		};

		if (terminatedWorkflows.length > 0) {
			resumeAttempt.terminatedPrevious = terminatedWorkflows.join(",");
		}

		if (checkpointHash) {
			resumeAttempt.resumedFromCheckpoint = checkpointHash;
		}

		this.data.session.resumeAttempts.push(resumeAttempt);

		await this.save();
	}

	/** Recalculate aggregations (total duration, phases). */
	private recalculateAggregations(): void {
		if (!this.data) return;

		const agents = this.data.metrics.agents;

		// Only count successful agents
		const successfulAgents = Object.entries(agents).filter(
			([, data]) => data.status === "success",
		);

		const totalDuration = successfulAgents.reduce(
			(sum, [, data]) => sum + data.final_duration_ms,
			0,
		);

		this.data.metrics.total_duration_ms = totalDuration;

		// Calculate phase-level metrics
		this.data.metrics.phases = calculatePhaseMetrics(
			successfulAgents,
			totalDuration,
		);
	}

	/** Get current metrics. */
	getMetrics(): SessionData {
		return JSON.parse(JSON.stringify(this.data)) as SessionData;
	}

	/** Save metrics to session.json (atomic write). */
	private async save(): Promise<void> {
		if (!this.data) return;
		await atomicWrite(this.sessionJsonPath, this.data);
	}

	/** Reload metrics from disk. */
	async reload(): Promise<void> {
		this.data = await readJson<SessionData>(this.sessionJsonPath);
	}
}
