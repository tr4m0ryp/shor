// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Workflow Logger
 *
 * Provides a unified, human-readable log file per workflow.
 * Optimized for `tail -f` viewing during concurrent workflow execution.
 */

import fs from "node:fs/promises";
import { formatDuration } from "../../utils/formatting.js";
import { LogStream } from "../log-stream.js";
import { generateWorkflowLogPath, type SessionMetadata } from "../utils.js";
import { formatLogTime, formatToolParams } from "./formatters.js";
import {
	buildCompletionBlock,
	buildInitHeader,
	buildResumeHeader,
} from "./headers.js";
import type { AgentLogDetails, WorkflowSummary } from "./types.js";

/** WorkflowLogger - Manages the unified workflow log file. */
export class WorkflowLogger {
	private readonly sessionMetadata: SessionMetadata;
	private readonly logStream: LogStream;
	private workflowId: string | undefined;

	constructor(sessionMetadata: SessionMetadata) {
		this.sessionMetadata = sessionMetadata;
		const logPath = generateWorkflowLogPath(sessionMetadata);
		this.logStream = new LogStream(logPath);
	}

	/** Initialize the log stream (creates file and writes header). */
	async initialize(workflowId?: string): Promise<void> {
		if (workflowId) {
			this.workflowId = workflowId;
		}

		if (this.logStream.isOpen) {
			return;
		}

		await this.logStream.open();

		// Write header only if file is new (empty)
		const stats = await fs.stat(this.logStream.path).catch(() => null);
		if (!stats || stats.size === 0) {
			await this.logStream.write(
				buildInitHeader(this.workflowId, this.sessionMetadata),
			);
		}
	}

	/** Write resume header to log file when workflow is resumed. */
	async logResumeHeader(resumeInfo: {
		previousWorkflowId: string;
		newWorkflowId: string;
		checkpointHash: string;
		completedAgents: string[];
	}): Promise<void> {
		await this.ensureInitialized();
		return this.logStream.write(buildResumeHeader(resumeInfo));
	}

	/** Log a phase transition event. */
	async logPhase(phase: string, event: "start" | "complete"): Promise<void> {
		await this.ensureInitialized();

		const action = event === "start" ? "Starting" : "Completed";
		const line = `[${formatLogTime()}] [PHASE] ${action}: ${phase}\n`;

		// Add blank line before phase start for readability
		if (event === "start") {
			await this.logStream.write("\n");
		}

		await this.logStream.write(line);
	}

	/** Log an agent event. */
	async logAgent(
		agentName: string,
		event: "start" | "end",
		details?: AgentLogDetails,
	): Promise<void> {
		await this.ensureInitialized();

		let message: string;

		if (event === "start") {
			const attempt = details?.attemptNumber ?? 1;
			message = `${agentName}: Starting (attempt ${attempt})`;
		} else {
			const parts: string[] = [`${agentName}:`];

			if (details?.success === false) {
				parts.push("Failed");
				if (details?.error) {
					parts.push(`- ${details.error}`);
				}
			} else {
				parts.push("Completed");
			}

			if (details?.duration_ms !== undefined) {
				parts.push(`(${formatDuration(details.duration_ms)})`);
			}

			message = parts.join(" ");
		}

		const line = `[${formatLogTime()}] [AGENT] ${message}\n`;
		await this.logStream.write(line);
	}

	/** Log a general event. */
	async logEvent(eventType: string, message: string): Promise<void> {
		await this.ensureInitialized();

		const line = `[${formatLogTime()}] [${eventType.toUpperCase()}] ${message}\n`;
		await this.logStream.write(line);
	}

	/** Log an error. */
	async logError(error: Error, context?: string): Promise<void> {
		await this.ensureInitialized();

		const contextStr = context ? ` (${context})` : "";
		const line = `[${formatLogTime()}] [ERROR] ${error.message}${contextStr}\n`;
		await this.logStream.write(line);
	}

	/** Log tool start event. */
	async logToolStart(
		agentName: string,
		toolName: string,
		parameters: unknown,
	): Promise<void> {
		await this.ensureInitialized();

		const params = formatToolParams(toolName, parameters);
		const paramStr = params ? `: ${params}` : "";
		const line = `[${formatLogTime()}] [${agentName}] [TOOL] ${toolName}${paramStr}\n`;
		await this.logStream.write(line);
	}

	/** Log LLM response. */
	async logLlmResponse(
		agentName: string,
		turn: number,
		content: string,
	): Promise<void> {
		await this.ensureInitialized();

		// Show full content, replacing newlines with escaped version for single-line output
		const escaped = content.replace(/\n/g, "\\n");
		const line = `[${formatLogTime()}] [${agentName}] [LLM] Turn ${turn}: ${escaped}\n`;
		await this.logStream.write(line);
	}

	/** Log workflow completion with full summary. */
	async logWorkflowComplete(summary: WorkflowSummary): Promise<void> {
		await this.ensureInitialized();

		// Single atomic write to prevent interleaved/duplicate output in log tailers
		await this.logStream.write(
			buildCompletionBlock(summary, this.workflowId, this.sessionMetadata),
		);
	}

	/** Ensure initialized (helper for lazy initialization). */
	private async ensureInitialized(): Promise<void> {
		if (!this.logStream.isOpen) {
			await this.initialize();
		}
	}

	/** Close the log stream. */
	async close(): Promise<void> {
		return this.logStream.close();
	}
}
