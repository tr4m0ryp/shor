// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { query } from "@anthropic-ai/claude-agent-sdk";
import { PentestError } from "../../services/error-handling.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { Timer } from "../../utils/metrics.js";
import type { createAuditLogger } from "../audit-logger.js";
import { dispatchMessage } from "../message-handlers.js";
import type { detectExecutionContext } from "../output-formatters.js";
import type { createProgressManager } from "../progress-manager.js";
import { getActualModelName } from "../router-utils.js";
import { startLivenessMonitor } from "./liveness/index.js";
import {
	createWatchdogState,
	recordAssistantTurn,
	shouldTrigger,
	fire as watchdogFire,
} from "./watchdog.js";

export interface MessageLoopResult {
	turnCount: number;
	result: string | null;
	apiErrorDetected: boolean;
	inputTokens?: number;
	outputTokens?: number;
	cacheReadInputTokens?: number;
	cacheCreationInputTokens?: number;
	numTurns?: number;
	model?: string | undefined;
	structuredOutput?: unknown;
}

export interface MessageLoopDeps {
	execContext: ReturnType<typeof detectExecutionContext>;
	description: string;
	progress: ReturnType<typeof createProgressManager>;
	auditLogger: ReturnType<typeof createAuditLogger>;
	logger: ActivityLogger;
	/** Owning agent — threaded to the dispatcher for per-agent skill attribution. */
	agentName?: string | null;
}

/**
 * Drive the Claude Agent SDK message stream to completion. Translates dispatcher decisions
 * (continue / complete / throw) into a single aggregate result for the caller.
 */
export async function processMessageStream(
	fullPrompt: string,
	options: NonNullable<Parameters<typeof query>[0]["options"]>,
	deps: MessageLoopDeps,
	timer: Timer,
): Promise<MessageLoopResult> {
	const { execContext, description, progress, auditLogger, logger, agentName } = deps;
	const HEARTBEAT_INTERVAL = 30000;

	let turnCount = 0;
	let result: string | null = null;
	let apiErrorDetected = false;
	let inputTokens: number | undefined;
	let outputTokens: number | undefined;
	let cacheReadInputTokens: number | undefined;
	let cacheCreationInputTokens: number | undefined;
	let numTurns: number | undefined;
	let model: string | undefined;
	let structuredOutput: unknown | undefined;
	let lastHeartbeat = Date.now();
	const watchdog = createWatchdogState();

	for await (const message of query({ prompt: fullPrompt, options })) {
		// Heartbeat logging when loader is disabled
		const now = Date.now();
		if (
			global.STORRON_DISABLE_LOADER &&
			now - lastHeartbeat > HEARTBEAT_INTERVAL
		) {
			logger.info(
				`[${Math.floor((now - timer.startTime) / 1000)}s] ${description} running... (Turn ${turnCount})`,
			);
			lastHeartbeat = now;
		}

		// Increment turn count for assistant messages
		if (message.type === "assistant") {
			turnCount++;
			// Feed the watchdog with this turn's text + tool-call commands so it can
			// detect stagnation (background-task feedback loops) and post-save loitering.
			const { text, commands } = extractAssistantSignals(message);
			recordAssistantTurn(watchdog, turnCount, text, commands);
			const trigger = shouldTrigger(watchdog, turnCount);
			if (trigger) {
				watchdogFire(watchdog, trigger, logger);
				break;
			}
		}

		const dispatchResult = await dispatchMessage(
			message as { type: string; subtype?: string },
			turnCount,
			{
				execContext,
				description,
				progress,
				auditLogger,
				logger,
				agentName: agentName ?? null,
			},
		);

		if (dispatchResult.type === "throw") {
			throw dispatchResult.error;
		}

		if (dispatchResult.type === "complete") {
			result = dispatchResult.result;
			inputTokens = dispatchResult.inputTokens;
			outputTokens = dispatchResult.outputTokens;
			cacheReadInputTokens = dispatchResult.cacheReadInputTokens;
			cacheCreationInputTokens = dispatchResult.cacheCreationInputTokens;
			numTurns = dispatchResult.numTurns;
			if (dispatchResult.structuredOutput !== undefined) {
				structuredOutput = dispatchResult.structuredOutput;
			}
			break;
		}

		if (dispatchResult.type === "continue") {
			if (dispatchResult.apiErrorDetected) {
				apiErrorDetected = true;
			}
			// Capture model from SystemInitMessage, but override with router model if applicable
			if (dispatchResult.model) {
				model = getActualModelName(dispatchResult.model);
			}
		}
	}

	return {
		turnCount,
		result,
		apiErrorDetected,
		model,
		...(inputTokens !== undefined && { inputTokens }),
		...(outputTokens !== undefined && { outputTokens }),
		...(cacheReadInputTokens !== undefined && { cacheReadInputTokens }),
		...(cacheCreationInputTokens !== undefined && { cacheCreationInputTokens }),
		...(numTurns !== undefined && { numTurns }),
		...(structuredOutput !== undefined && { structuredOutput }),
	};
}

interface AssistantMessageContent {
	readonly type: string;
	readonly text?: string;
	readonly thinking?: string;
	readonly name?: string;
	readonly input?: { readonly command?: unknown };
}

interface AssistantMessage {
	readonly message?: { readonly content?: readonly AssistantMessageContent[] };
}

/**
 * Pull plain-text content and Bash tool-call commands out of an assistant
 * message so the watchdog can pattern-match against them. Keeps the SDK
 * message shape contained here — the watchdog itself takes plain strings.
 */
function extractAssistantSignals(message: unknown): {
	text: string;
	commands: readonly string[];
} {
	const content = (message as AssistantMessage)?.message?.content ?? [];
	const texts: string[] = [];
	const commands: string[] = [];
	for (const block of content) {
		if (block.type === "text" && typeof block.text === "string") {
			texts.push(block.text);
		} else if (
			block.type === "thinking" &&
			typeof block.thinking === "string"
		) {
			texts.push(block.thinking);
		} else if (block.type === "tool_use" && block.name === "Bash") {
			const cmd = block.input?.command;
			if (typeof cmd === "string") commands.push(cmd);
		}
	}
	return { text: texts.join("\n"), commands };
}
