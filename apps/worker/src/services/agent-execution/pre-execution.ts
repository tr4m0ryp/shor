// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Pre-execution stages for an agent run.
 *
 * Each helper handles one phase that must succeed before the Claude SDK is
 * invoked: config loading, prompt rendering, and the git checkpoint. They
 * return `Result<T, PentestError>` so the orchestrator can short-circuit on
 * the first failure.
 */

import type { AuditSession } from "../../audit/index.js";
import { AGENTS } from "../../session-manager.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentName } from "../../types/agents.js";
import { ErrorCode } from "../../types/errors.js";
import { err, isErr, ok, type Result } from "../../types/result.js";
import type { ConfigLoaderService } from "../config-loader.js";
import type { Container } from "../container.js";
import { PentestError } from "../error-handling.js";
import { createGitCheckpoint } from "../git-manager.js";
import { loadPrompt } from "../prompt-manager.js";
import type { PromptContext } from "../prompt-manager/prompt-context.js";
import { assembleScanPromptContext } from "../threat-model/index.js";

/**
 * Resolve the distributed config from any of the accepted forms (pre-parsed
 * object, raw YAML, or file path).
 */
export async function loadDistributedConfig(
	configLoader: ConfigLoaderService,
	configPath: string | undefined,
	configData: import("../../types/config.js").DistributedConfig | undefined,
	configYAML: string | undefined,
): Promise<
	Result<import("../../types/config.js").DistributedConfig | null, PentestError>
> {
	return configLoader.loadOptional(configPath, configData, configYAML);
}

/**
 * Render the prompt template for the given agent, wrapping any failure in a
 * `PROMPT_LOAD_FAILED` `PentestError`. `promptContext` carries the assembled
 * per-scan values ({{THREAT_MODEL}} and siblings); absent fields fall back to
 * the neutral "(none)" sentinel inside `loadPrompt`.
 */
export async function loadAgentPrompt(
	agentName: AgentName,
	webUrl: string,
	repoPath: string,
	distributedConfig: import("../../types/config.js").DistributedConfig | null,
	logger: ActivityLogger,
	promptDir: string | undefined,
	promptContext: PromptContext = {},
): Promise<Result<string, PentestError>> {
	const promptTemplate = AGENTS[agentName].promptTemplate;
	try {
		const prompt = await loadPrompt(
			promptTemplate,
			{ webUrl, repoPath },
			distributedConfig,
			logger,
			promptDir,
			promptContext,
		);
		return ok(prompt);
	} catch (error) {
		const errorMessage = error instanceof Error ? error.message : String(error);
		return err(
			new PentestError(
				`Failed to load prompt for ${agentName}: ${errorMessage}`,
				"prompt",
				false,
				{ agentName, promptTemplate, originalError: errorMessage },
				ErrorCode.PROMPT_LOAD_FAILED,
			),
		);
	}
}

/**
 * Create a git checkpoint before agent execution, wrapping any failure in a
 * `GIT_CHECKPOINT_FAILED` `PentestError`.
 */
export async function checkpointWorkspace(
	agentName: AgentName,
	deliverablesPath: string,
	attemptNumber: number,
	logger: ActivityLogger,
): Promise<Result<void, PentestError>> {
	try {
		await createGitCheckpoint(
			deliverablesPath,
			agentName,
			attemptNumber,
			logger,
		);
		return ok(undefined);
	} catch (error) {
		const errorMessage = error instanceof Error ? error.message : String(error);
		return err(
			new PentestError(
				`Failed to create git checkpoint for ${agentName}: ${errorMessage}`,
				"filesystem",
				false,
				{ agentName, deliverablesPath, originalError: errorMessage },
				ErrorCode.GIT_CHECKPOINT_FAILED,
			),
		);
	}
}

/**
 * Run all pre-execution stages and return the resolved prompt + config.
 * Returns the first failure encountered.
 *
 * `_container` is retained for interface stability; the engine no longer
 * performs any container-driven preflight before agent execution.
 */
export async function runPreExecution(
	configLoader: ConfigLoaderService,
	agentName: AgentName,
	webUrl: string,
	repoPath: string,
	deliverablesPath: string,
	attemptNumber: number,
	configPath: string | undefined,
	configData: import("../../types/config.js").DistributedConfig | undefined,
	configYAML: string | undefined,
	promptDir: string | undefined,
	logger: ActivityLogger,
	_container: Container | undefined,
	auditSession: AuditSession,
): Promise<Result<{ prompt: string }, PentestError>> {
	// 1. Load config (pre-parsed configData -> raw YAML -> file path)
	const configResult = await loadDistributedConfig(
		configLoader,
		configPath,
		configData,
		configYAML,
	);
	if (isErr(configResult)) {
		return configResult;
	}
	const distributedConfig = configResult.value;

	// 1b. Assemble the per-scan prompt context (threat model + sibling artifacts).
	// Every source is optional — early agents (before threat_model.json exists)
	// get an empty context and the placeholders render as "(none)".
	const promptContext = await assembleScanPromptContext(
		deliverablesPath,
		distributedConfig,
		process.env,
		webUrl,
	);

	// 2. Load prompt
	const promptResult = await loadAgentPrompt(
		agentName,
		webUrl,
		repoPath,
		distributedConfig,
		logger,
		promptDir,
		promptContext,
	);
	if (isErr(promptResult)) {
		return promptResult;
	}
	const prompt = promptResult.value;

	// 3. Create git checkpoint before execution
	const checkpointResult = await checkpointWorkspace(
		agentName,
		deliverablesPath,
		attemptNumber,
		logger,
	);
	if (isErr(checkpointResult)) {
		return checkpointResult;
	}

	// 4. Start audit logging
	await auditSession.startAgent(agentName, prompt, attemptNumber);

	return ok({ prompt });
}
