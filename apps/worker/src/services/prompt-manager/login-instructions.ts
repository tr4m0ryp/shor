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
 * Stable, NON-SECRET seam tokens left in prompt text in place of plaintext
 * credentials/TOTP (ADR-050). The login still happens at runtime, but the
 * actual material is supplied out-of-band (file-mounted / injected by the
 * browser-driver), never baked into the prompt string a model can echo or log.
 */
export const CREDENTIAL_SEAM = {
	username: "{{SHOR_LOGIN_USERNAME}}",
	password: "{{SHOR_LOGIN_PASSWORD}}",
	totp: 'a generated TOTP code (from the run-injected secret, placeholder "{{SHOR_LOGIN_TOTP}}")',
	totpSecret: "{{SHOR_LOGIN_TOTP_SECRET}}",
} as const;

/**
 * Build complete login instructions from authentication config.
 * Loads the shared template, extracts the relevant sections per login_type,
 * and substitutes NON-SECRET seam tokens for credential/TOTP placeholders
 * (ADR-050). No plaintext credential or TOTP secret is ever interpolated into
 * the returned prompt text; the runtime resolves the seam tokens out-of-band.
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

		// 4. Substitute NON-SECRET seam tokens for credential/TOTP placeholders.
		//    ADR-050: plaintext credentials and the TOTP secret are NEVER baked
		//    into prompt text. The login flow's $username/$password/$totp markers
		//    become stable seam tokens the runtime resolves out-of-band; whether a
		//    credential exists is derived from config presence, not its value.
		const hasUsername = Boolean(authentication.credentials?.username);
		const hasPassword = Boolean(authentication.credentials?.password);
		const hasTotp = Boolean(authentication.credentials?.totp_secret);

		let userInstructions = (authentication.login_flow ?? []).join("\n");
		if (hasUsername) {
			userInstructions = userInstructions.replace(
				/\$username/g,
				CREDENTIAL_SEAM.username,
			);
		}
		if (hasPassword) {
			userInstructions = userInstructions.replace(
				/\$password/g,
				CREDENTIAL_SEAM.password,
			);
		}
		if (hasTotp) {
			userInstructions = userInstructions.replace(
				/\$totp/g,
				CREDENTIAL_SEAM.totp,
			);
		}

		loginInstructions = loginInstructions.replace(
			/{{user_instructions}}/g,
			userInstructions,
		);

		// 5. Replace the TOTP secret template marker with a seam token — never the
		//    secret itself (ADR-050).
		if (hasTotp) {
			loginInstructions = loginInstructions.replace(
				/{{totp_secret}}/g,
				CREDENTIAL_SEAM.totpSecret,
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
