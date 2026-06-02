// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from "zx";
import { PROMPTS_DIR } from "../../paths.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { Authentication } from "../../types/config.js";
import { PentestError } from "../error-handling.js";

/**
 * Build complete login instructions from authentication config.
 * Loads the shared template, extracts the relevant sections per login_type,
 * and interpolates credentials/TOTP placeholders.
 */
export async function buildLoginInstructions(
	authentication: Authentication,
	logger: ActivityLogger,
	promptsBaseDir: string = PROMPTS_DIR,
): Promise<string> {
	try {
		// 1. Load the login instructions template
		const loginInstructionsPath = path.join(
			promptsBaseDir,
			"shared",
			"login-instructions.txt",
		);

		if (!(await fs.pathExists(loginInstructionsPath))) {
			throw new PentestError(
				"Login instructions template not found",
				"filesystem",
				false,
				{ loginInstructionsPath },
			);
		}

		const fullTemplate = await fs.readFile(loginInstructionsPath, "utf8");

		const getSection = (content: string, sectionName: string): string => {
			const regex = new RegExp(
				`<!-- BEGIN:${sectionName} -->([\\s\\S]*?)<!-- END:${sectionName} -->`,
				"g",
			);
			const match = regex.exec(content);
			return match?.[1]?.trim() ?? "";
		};

		// 2. Extract sections based on login type
		const loginType = authentication.login_type?.toUpperCase();
		let loginInstructions = "";

		const commonSection = getSection(fullTemplate, "COMMON");
		const authSection = loginType ? getSection(fullTemplate, loginType) : ""; // FORM or SSO
		const verificationSection = getSection(fullTemplate, "VERIFICATION");

		// 3. Assemble instructions from sections (fallback to full template if markers missing)
		if (!commonSection && !authSection && !verificationSection) {
			logger.warn(
				"Section markers not found, using full login instructions template",
			);
			loginInstructions = fullTemplate;
		} else {
			loginInstructions = [commonSection, authSection, verificationSection]
				.filter((section) => section)
				.join("\n\n");
		}

		// 4. Interpolate login flow and credential placeholders
		let userInstructions = (authentication.login_flow ?? []).join("\n");

		if (authentication.credentials) {
			if (authentication.credentials.username) {
				userInstructions = userInstructions.replace(
					/\$username/g,
					authentication.credentials.username,
				);
			}
			if (authentication.credentials.password) {
				userInstructions = userInstructions.replace(
					/\$password/g,
					authentication.credentials.password,
				);
			}
			if (authentication.credentials.totp_secret) {
				userInstructions = userInstructions.replace(
					/\$totp/g,
					`generated TOTP code using secret "${authentication.credentials.totp_secret}"`,
				);
			}
		}

		loginInstructions = loginInstructions.replace(
			/{{user_instructions}}/g,
			userInstructions,
		);

		// 5. Replace TOTP secret placeholder if present in template
		if (authentication.credentials?.totp_secret) {
			loginInstructions = loginInstructions.replace(
				/{{totp_secret}}/g,
				authentication.credentials.totp_secret,
			);
		}

		return loginInstructions;
	} catch (error) {
		if (error instanceof PentestError) {
			throw error;
		}
		const errMsg = error instanceof Error ? error.message : String(error);
		throw new PentestError(
			`Failed to build login instructions: ${errMsg}`,
			"config",
			false,
			{
				authentication,
				originalError: errMsg,
			},
		);
	}
}
