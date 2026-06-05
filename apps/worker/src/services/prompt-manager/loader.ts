// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from "zx";
import { PROMPTS_DIR } from "../../paths.js";
import { PLAYWRIGHT_SESSION_MAPPING } from "../../session-manager.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { DistributedConfig } from "../../types/config.js";
import { handlePromptError, PentestError } from "../error-handling.js";
import { processIncludes } from "./includes.js";
import { interpolateVariables } from "./interpolation.js";
import type { PromptContext } from "./prompt-context.js";
import { recommendedSkillsSection } from "./skill-recommendations.js";
import { selectPreReconTemplate } from "./template-selection.js";
import type { PromptVariables } from "./types.js";

/**
 * Resolve a prompt file by basename under `baseDir`. Prefers a direct hit at the
 * root, then searches the category subdirs (prompts are organised into
 * recon/ vulnerability/ exploitation/ reporting/ attack-surface/). Returns the
 * absolute path, or undefined if not found anywhere.
 */
async function resolvePromptFile(baseDir: string, filename: string): Promise<string | undefined> {
	const direct = path.join(baseDir, filename);
	if (await fs.pathExists(direct)) return direct;
	const stack: string[] = [baseDir];
	while (stack.length > 0) {
		const dir = stack.pop();
		if (dir === undefined) break;
		const entries = await fs.readdir(dir, { withFileTypes: true });
		for (const entry of entries) {
			const full = path.join(dir, entry.name);
			if (entry.isDirectory()) stack.push(full);
			else if (entry.name === filename) return full;
		}
	}
	return undefined;
}

/**
 * Load a named prompt template, resolve `@include(...)` directives, and
 * interpolate variables. The pre-recon agent always resolves to its
 * clearnet template. `context` carries the optional per-round prompt-context
 * values ({{THREAT_MODEL}}, {{PARTITION}}, {{IDENTITIES}}, ...); omit it and the
 * placeholders fall back to neutral sentinels.
 */
export async function loadPrompt(
	promptName: string,
	variables: PromptVariables,
	config: DistributedConfig | null = null,
	logger: ActivityLogger,
	promptDir?: string,
	context: PromptContext = {},
): Promise<string> {
	try {
		// 1. Resolve prompt file path (promptDir override → default PROMPTS_DIR).
		//    Pre-recon resolves to its clearnet template; every other prompt loads
		//    its bare filename.
		const basePromptsDir = promptDir ?? PROMPTS_DIR;
		const promptFilename =
			promptName === "pre-recon-code"
				? selectPreReconTemplate(variables.webUrl)
				: `${promptName}.txt`;
		// Prompts live in category subdirs; resolve by basename (root or subdir).
		const promptPath = await resolvePromptFile(basePromptsDir, promptFilename);

		if (promptPath === undefined) {
			throw new PentestError(
				`Prompt file not found: ${promptFilename} under ${basePromptsDir}`,
				"prompt",
				false,
				{ promptName, basePromptsDir },
			);
		}

		// 2. Assign Playwright session based on agent name
		const enhancedVariables: PromptVariables = { ...variables };

		const session =
			PLAYWRIGHT_SESSION_MAPPING[
				promptName as keyof typeof PLAYWRIGHT_SESSION_MAPPING
			];
		if (session) {
			enhancedVariables.PLAYWRIGHT_SESSION = session;
			logger.info(
				`Assigned ${promptName} -> ${enhancedVariables.PLAYWRIGHT_SESSION}`,
			);
		} else {
			enhancedVariables.PLAYWRIGHT_SESSION = "agent1";
			logger.warn(
				`Unknown agent ${promptName}, using fallback -> ${enhancedVariables.PLAYWRIGHT_SESSION}`,
			);
		}

		// 3. Read template file
		let template = await fs.readFile(promptPath, "utf8");

		// 4. Process @include directives
		template = await processIncludes(template, basePromptsDir);

		// 5. Interpolate variables, then append this agent's recommended-skills
		//    footer (soft scoping — steers tool choice without restricting).
		const interpolated = await interpolateVariables(
			template,
			enhancedVariables,
			config,
			logger,
			basePromptsDir,
			context,
		);
		return interpolated + recommendedSkillsSection(promptName);
	} catch (error) {
		if (error instanceof PentestError) {
			throw error;
		}
		const promptError = handlePromptError(promptName, error as Error);
		throw promptError.error;
	}
}
