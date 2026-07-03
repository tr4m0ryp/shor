// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { PROMPTS_DIR } from "../../paths.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { DistributedConfig } from "../../types/config.js";
import { PentestError } from "../error-handling.js";
import { buildAuthContext } from "./auth-context.js";
import { buildLoginInstructions } from "./login-instructions.js";
import { applyPromptContext, type PromptContext } from "./prompt-context.js";
import type { PromptVariables } from "./types.js";

/**
 * Replace every `{{VARIABLE}}` placeholder in a prompt template using values
 * from `variables`, the optional `DistributedConfig`, and (when applicable) the
 * assembled login instructions, and the optional per-round `PromptContext`.
 * Warns the logger about any leftover placeholders without failing.
 */
export async function interpolateVariables(
	template: string,
	variables: PromptVariables,
	config: DistributedConfig | null = null,
	logger: ActivityLogger,
	promptsBaseDir: string = PROMPTS_DIR,
	context: PromptContext = {},
): Promise<string> {
	try {
		if (!template || typeof template !== "string") {
			throw new PentestError(
				"Template must be a non-empty string",
				"validation",
				false,
				{
					templateType: typeof template,
					templateLength: template?.length,
				},
			);
		}

		if (!variables || !variables.webUrl || !variables.repoPath) {
			throw new PentestError(
				"Variables must include webUrl and repoPath",
				"validation",
				false,
				{
					variables: Object.keys(variables || {}),
				},
			);
		}

		let result = template
			.replace(/{{WEB_URL}}/g, variables.webUrl)
			.replace(/{{REPO_PATH}}/g, variables.repoPath)
			.replace(
				/{{PLAYWRIGHT_SESSION}}/g,
				variables.PLAYWRIGHT_SESSION || "agent1",
			)
			.replace(
				/{{AUTH_CONTEXT}}/g,
				buildAuthContext(config, context.identities),
			)
			.replace(
				/{{DESCRIPTION}}/g,
				config?.description ? `Description: ${config.description}` : "",
			);

		// Resolve the per-round prompt-context placeholders ({{THREAT_MODEL}},
		// {{HISTORICAL_SEED}}, {{RAG_EXEMPLARS}}, {{PARTITION}}, {{LENS}},
		// {{VOTER_INDEX}}, {{IDENTITIES}}, {{FP_RULES}}). Absent values collapse to
		// a neutral sentinel so none ever survives as a literal placeholder
		// downstream.
		result = applyPromptContext(result, context);

		if (config) {
			// Handle rules section - if both are empty, use cleaner messaging
			const hasAvoidRules = config.avoid && config.avoid.length > 0;
			const hasFocusRules = config.focus && config.focus.length > 0;

			if (!hasAvoidRules && !hasFocusRules) {
				// Replace the entire rules section with a clean message
				const cleanRulesSection =
					"<rules>\nNo specific rules or focus areas provided for this test.\n</rules>";
				result = result.replace(/<rules>[\s\S]*?<\/rules>/g, cleanRulesSection);
			} else {
				const avoidRules = hasAvoidRules
					? config.avoid?.map((r) => `- ${r.description}`).join("\n")
					: "None";
				const focusRules = hasFocusRules
					? config.focus?.map((r) => `- ${r.description}`).join("\n")
					: "None";

				result = result
					.replace(/{{RULES_AVOID}}/g, avoidRules)
					.replace(/{{RULES_FOCUS}}/g, focusRules);
			}

			// Extract and inject login instructions from config
			if (config.authentication?.login_flow) {
				const loginInstructions = await buildLoginInstructions(
					config.authentication,
					logger,
					promptsBaseDir,
				);
				result = result.replace(/{{LOGIN_INSTRUCTIONS}}/g, loginInstructions);
			} else {
				result = result.replace(/{{LOGIN_INSTRUCTIONS}}/g, "");
			}
		} else {
			// Replace the entire rules section with a clean message when no config provided
			const cleanRulesSection =
				"<rules>\nNo specific rules or focus areas provided for this test.\n</rules>";
			result = result.replace(/<rules>[\s\S]*?<\/rules>/g, cleanRulesSection);
			result = result.replace(/{{LOGIN_INSTRUCTIONS}}/g, "");
		}

		// Validate that all placeholders have been replaced (excluding instructional text)
		const remainingPlaceholders = result.match(/\{\{[^}]+\}\}/g);
		if (remainingPlaceholders) {
			logger.warn(
				`Found unresolved placeholders in prompt: ${remainingPlaceholders.join(", ")}`,
			);
		}

		return result;
	} catch (error) {
		if (error instanceof PentestError) {
			throw error;
		}
		const errMsg = error instanceof Error ? error.message : String(error);
		throw new PentestError(
			`Variable interpolation failed: ${errMsg}`,
			"prompt",
			false,
			{ originalError: errMsg },
		);
	}
}
