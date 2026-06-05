// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Post-execution stages for an agent run.
 *
 * Each helper handles one phase that runs after the Claude SDK returns:
 * spending-cap detection, structured-output persistence, deliverable
 * validation, and the success-commit + audit finalization.
 */

import { fs, path } from "zx";
import {
	type ClaudePromptResult,
	validateAgentOutput,
} from "../../ai/claude-executor.js";
import { getQueueFilename } from "../../ai/queue-schemas.js";
import type { AuditSession } from "../../audit/index.js";
import { AGENTS } from "../../session-manager.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentName } from "../../types/agents.js";
import type { AgentEndResult } from "../../types/audit.js";
import { ErrorCode } from "../../types/errors.js";
import { ok, type Result } from "../../types/result.js";
import { isSpendingCapBehavior } from "../../utils/billing-detection.js";
import { isRefusalBehavior } from "../../utils/refusal-detection.js";
import { failAgent } from "../agent-execution-internal.js";
import type { CoverageResult } from "../coverage/index.js";
import type { PentestError } from "../error-handling.js";
import { commitGitSuccess, getGitCommitHash } from "../git-manager.js";

/**
 * Defense-in-depth check that catches Claude returning a billing/spending-cap
 * message instead of doing the work. When detected, rolls back and surfaces a
 * retryable `SPENDING_CAP_REACHED` error.
 *
 * Returns `null` when the agent's behavior does not match the spending-cap
 * pattern (caller should continue).
 */
export async function checkSpendingCap(
	agentName: AgentName,
	deliverablesPath: string,
	auditSession: AuditSession,
	logger: ActivityLogger,
	attemptNumber: number,
	result: ClaudePromptResult,
): Promise<Result<AgentEndResult, PentestError> | null> {
	if (!(result.success && (result.turns ?? 0) <= 2)) {
		return null;
	}
	const resultText = result.result || "";
	if (!isSpendingCapBehavior(result.turns ?? 0, resultText)) {
		return null;
	}
	return failAgent(agentName, deliverablesPath, auditSession, logger, {
		attemptNumber,
		result,
		rollbackReason: "spending cap detected",
		errorMessage: `Spending cap likely reached: ${resultText.slice(0, 100)}`,
		errorCode: ErrorCode.SPENDING_CAP_REACHED,
		category: "billing",
		retryable: true,
		context: { agentName, turns: result.turns },
	});
}

/**
 * Defense-in-depth check that catches the model declining the authorized task as
 * "cyber content" and returning a short refusal instead of doing the work. The
 * SDK reports success, so without this the refusal would pass through as "no
 * findings" — the offensive lane produces no evidence and a real finding is
 * stranded at `firm` instead of being promoted to `confirmed` (or honestly
 * failing the lane). Rolls back and surfaces a RETRYABLE error: the retry
 * re-runs under the strengthened authorization preamble; a persistent refusal
 * fails the lane, which the findings gate turns into an honest
 * `unverified_out_of_scope` demotion rather than an as-if-tested emission.
 *
 * Returns `null` when the behavior does not match a refusal (caller continues).
 */
export async function checkRefusal(
	agentName: AgentName,
	deliverablesPath: string,
	auditSession: AuditSession,
	logger: ActivityLogger,
	attemptNumber: number,
	result: ClaudePromptResult,
): Promise<Result<AgentEndResult, PentestError> | null> {
	if (!(result.success && (result.turns ?? 0) <= 2)) {
		return null;
	}
	const resultText = result.result || "";
	if (!isRefusalBehavior(result.turns ?? 0, resultText)) {
		return null;
	}
	return failAgent(agentName, deliverablesPath, auditSession, logger, {
		attemptNumber,
		result,
		rollbackReason: "model refusal",
		errorMessage: `Model refused the authorized task: ${resultText.slice(0, 100)}`,
		errorCode: ErrorCode.AGENT_EXECUTION_FAILED,
		category: "validation",
		retryable: true,
		context: { agentName, turns: result.turns },
	});
}

/**
 * Handle a non-success `ClaudePromptResult` by rolling back and surfacing the
 * SDK's retryable hint via `failAgent`.
 */
export async function handleExecutionFailure(
	agentName: AgentName,
	deliverablesPath: string,
	auditSession: AuditSession,
	logger: ActivityLogger,
	attemptNumber: number,
	result: ClaudePromptResult,
): Promise<Result<AgentEndResult, PentestError>> {
	return failAgent(agentName, deliverablesPath, auditSession, logger, {
		attemptNumber,
		result,
		rollbackReason: "execution failure",
		errorMessage: result.error || "Agent execution failed",
		errorCode: ErrorCode.AGENT_EXECUTION_FAILED,
		category: "validation",
		retryable: result.retryable ?? true,
		context: { agentName, originalError: result.error },
	});
}

/**
 * Ensure a vuln agent's exploitation-queue file exists and is valid JSON.
 *
 * All-flash mode: the agent writes the queue file itself (the prompt instructs
 * the exact `{ "vulnerabilities": [...] }` shape). This backstops that:
 *   1. if the SDK still returned structured output, persist it (capable-model path);
 *   2. else if the agent's hand-written file parses, keep it;
 *   3. else write an empty valid queue so a flash hiccup degrades to "no
 *      findings" instead of failing queue validation and crashing the pipeline.
 * No-op for non-vuln agents.
 */
export async function writeStructuredOutput(
	agentName: AgentName,
	deliverablesPath: string,
	result: ClaudePromptResult,
	logger: ActivityLogger,
): Promise<void> {
	const queueFilename = getQueueFilename(agentName);
	if (!queueFilename) return;
	await fs.ensureDir(deliverablesPath);
	const queuePath = path.join(deliverablesPath, queueFilename);

	if (result.structuredOutput !== undefined) {
		await fs.writeFile(queuePath, JSON.stringify(result.structuredOutput, null, 2), "utf8");
		logger.info(`Wrote structured output queue to ${queueFilename}`);
		return;
	}

	// The agent should have written the queue itself; accept it if it parses,
	// else try to salvage it (flash sometimes wraps JSON in prose / ```json
	// fences or leaves a trailing comma) before degrading to an empty queue.
	if (await fs.pathExists(queuePath)) {
		const raw = await fs.readFile(queuePath, "utf8");
		const salvaged = parseQueue(raw);
		if (salvaged) {
			// Rewrite canonicalized so downstream validation reads clean JSON.
			await fs.writeFile(queuePath, JSON.stringify(salvaged, null, 2), "utf8");
			logger.info(`Using agent-written queue ${queueFilename} (${salvaged.vulnerabilities.length} entries)`);
			return;
		}
		logger.warn(`Queue ${queueFilename} unsalvageable; replacing with empty queue`);
	} else {
		logger.warn(`Queue ${queueFilename} missing; writing empty queue (no findings)`);
	}
	await fs.writeFile(queuePath, JSON.stringify({ vulnerabilities: [] }, null, 2), "utf8");
}

/** A parsed queue: `{ vulnerabilities: [...] }`. */
interface ParsedQueue {
	vulnerabilities: unknown[];
}

/**
 * Best-effort parse of a hand-written queue. Tries strict JSON first, then
 * salvages: strips ```json fences and prose, slices the outermost `{...}`, and
 * drops trailing commas. Returns null only when no `vulnerabilities` array can
 * be recovered.
 */
function parseQueue(raw: string): ParsedQueue | null {
	const tryParse = (s: string): ParsedQueue | null => {
		try {
			const v: unknown = JSON.parse(s);
			if (v && typeof v === "object" && Array.isArray((v as { vulnerabilities?: unknown }).vulnerabilities)) {
				return { vulnerabilities: (v as ParsedQueue).vulnerabilities };
			}
		} catch {
			/* fall through */
		}
		return null;
	};

	const direct = tryParse(raw);
	if (direct) return direct;

	// Strip code fences, then slice from the first `{` to the last `}`.
	let body = raw.replace(/```(?:json)?/gi, "");
	const start = body.indexOf("{");
	const end = body.lastIndexOf("}");
	if (start === -1 || end <= start) return null;
	body = body.slice(start, end + 1);

	return tryParse(body) ?? tryParse(body.replace(/,(\s*[}\]])/g, "$1"));
}

/**
 * Validate the deliverable file produced by the agent. On failure, rolls back
 * and surfaces a retryable `OUTPUT_VALIDATION_FAILED` error.
 */
export async function validateDeliverable(
	agentName: AgentName,
	deliverablesPath: string,
	auditSession: AuditSession,
	logger: ActivityLogger,
	attemptNumber: number,
	result: ClaudePromptResult,
): Promise<Result<AgentEndResult, PentestError> | null> {
	const validationPassed = await validateAgentOutput(
		result,
		agentName,
		deliverablesPath,
		logger,
	);
	if (validationPassed) {
		return null;
	}
	return failAgent(agentName, deliverablesPath, auditSession, logger, {
		attemptNumber,
		result,
		rollbackReason: "validation failure",
		errorMessage: `Agent ${agentName} failed output validation`,
		errorCode: ErrorCode.OUTPUT_VALIDATION_FAILED,
		category: "validation",
		retryable: true,
		context: {
			agentName,
			deliverableFilename: AGENTS[agentName].deliverableFilename,
		},
	});
}

/**
 * T4 last-resort coverage bridge.
 *
 * After the coverage loop converges and the deliverable validates, fail the
 * agent (retryably) when a REQUIRED tool was still never exercised. Reuses the
 * `OUTPUT_VALIDATION_FAILED` failAgent path so no new retry mechanism is added.
 * Returns `null` (continue to success) when there are no hard misses — the
 * default policy has `required = []`, so this is normally a no-op.
 */
export async function failOnHardMissing(
	agentName: AgentName,
	deliverablesPath: string,
	auditSession: AuditSession,
	logger: ActivityLogger,
	attemptNumber: number,
	result: ClaudePromptResult,
	coverage: CoverageResult,
): Promise<Result<AgentEndResult, PentestError> | null> {
	if (coverage.hardMissing.length === 0) {
		return null;
	}
	const missing = coverage.hardMissing.join(", ");
	return failAgent(agentName, deliverablesPath, auditSession, logger, {
		attemptNumber,
		result,
		rollbackReason: "required coverage tools missing",
		errorMessage: `Agent ${agentName} skipped required tools: ${missing}`,
		errorCode: ErrorCode.OUTPUT_VALIDATION_FAILED,
		category: "validation",
		retryable: true,
		context: { agentName, hardMissing: coverage.hardMissing },
	});
}

/**
 * Commit deliverables, capture the resulting hash, build the
 * `AgentEndResult`, and write the success record to the audit log.
 */
export async function finalizeSuccess(
	agentName: AgentName,
	deliverablesPath: string,
	auditSession: AuditSession,
	logger: ActivityLogger,
	attemptNumber: number,
	result: ClaudePromptResult,
): Promise<Result<AgentEndResult, PentestError>> {
	await commitGitSuccess(deliverablesPath, agentName, logger);
	const commitHash = await getGitCommitHash(deliverablesPath);

	const endResult: AgentEndResult = {
		attemptNumber,
		duration_ms: result.duration,
		success: true,
		model: result.model,
		...(commitHash && { checkpoint: commitHash }),
		...(result.inputTokens !== undefined && {
			input_tokens: result.inputTokens,
		}),
		...(result.outputTokens !== undefined && {
			output_tokens: result.outputTokens,
		}),
		...(result.cacheReadInputTokens !== undefined && {
			cache_read_input_tokens: result.cacheReadInputTokens,
		}),
		...(result.cacheCreationInputTokens !== undefined && {
			cache_creation_input_tokens: result.cacheCreationInputTokens,
		}),
		...(result.turns !== undefined && { num_turns: result.turns }),
	};
	await auditSession.endAgent(agentName, endResult);

	return ok(endResult);
}
