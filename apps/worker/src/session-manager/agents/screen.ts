// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { fs, path } from "zx";

import type { ActivityLogger } from "../../types/activity-logger.js";
import type {
	AgentDefinition,
	AgentName,
	AgentValidator,
	VulnType,
} from "../../types/index.js";

/**
 * Factory for screened-queue validators.
 *
 * The screened queue shares the exploitation queue's `{ vulnerabilities: [...] }`
 * shape but has NO paired markdown deliverable, so the shared
 * `validateQueueAndDeliverable` helper does not apply here: that helper demands a
 * symmetric deliverable+queue pair and is keyed to `VULN_TYPE_CONFIG`'s hardcoded
 * `*_exploitation_queue.json` filenames. We therefore validate the single
 * `*_screened_queue.json` directly, mirroring its JSON-structure check.
 *
 * An empty `vulnerabilities` array is VALID: a screen that adversarially refutes
 * every hypothesis in its category still produces a well-formed (empty) queue,
 * and the downstream exploit agent must handle that case gracefully.
 */
function createScreenValidator(vulnType: VulnType): AgentValidator {
	return async (
		sourceDir: string,
		logger: ActivityLogger,
	): Promise<boolean> => {
		const queuePath = path.join(sourceDir, `${vulnType}_screened_queue.json`);
		try {
			if (!(await fs.pathExists(queuePath))) {
				logger.warn(`Screened queue missing for ${vulnType}: ${queuePath}`);
				return false;
			}
			const parsed = JSON.parse(
				await fs.readFile(queuePath, "utf8"),
			) as unknown;
			const valid =
				typeof parsed === "object" &&
				parsed !== null &&
				"vulnerabilities" in parsed &&
				Array.isArray((parsed as { vulnerabilities: unknown }).vulnerabilities);
			if (!valid) {
				logger.warn(
					`Screened queue for ${vulnType} missing a valid 'vulnerabilities' array`,
				);
			}
			return valid;
		} catch (error) {
			const errMsg = error instanceof Error ? error.message : String(error);
			logger.warn(`Screen queue validation failed for ${vulnType}: ${errMsg}`);
			return false;
		}
	};
}

/**
 * Stub validator for the +2 new-category screen agents (logic, misconfig-web).
 * Mirrors the recon/exploit presence validators; task 005/009 fills the real
 * prompt and tightens this to the screened-queue structure check.
 */
function createNewCategoryScreenValidator(
	deliverableFilename: string,
): AgentValidator {
	return async (sourceDir: string): Promise<boolean> =>
		fs.pathExists(path.join(sourceDir, deliverableFilename));
}

export const screenAgents: Readonly<
	Record<Extract<AgentName, `${string}-screen`>, AgentDefinition>
> = Object.freeze({
	"injection-screen": {
		name: "injection-screen",
		displayName: "Injection screen agent",
		prerequisites: ["injection-vuln"],
		promptTemplate: "screen-injection",
		deliverableFilename: "injection_screened_queue.json",
		modelTier: "medium",
	},
	"xss-screen": {
		name: "xss-screen",
		displayName: "XSS screen agent",
		prerequisites: ["xss-vuln"],
		promptTemplate: "screen-xss",
		deliverableFilename: "xss_screened_queue.json",
		modelTier: "medium",
	},
	"auth-screen": {
		name: "auth-screen",
		displayName: "Auth screen agent",
		prerequisites: ["auth-vuln"],
		promptTemplate: "screen-auth",
		deliverableFilename: "auth_screened_queue.json",
		modelTier: "medium",
	},
	"ssrf-screen": {
		name: "ssrf-screen",
		displayName: "SSRF screen agent",
		prerequisites: ["ssrf-vuln"],
		promptTemplate: "screen-ssrf",
		deliverableFilename: "ssrf_screened_queue.json",
		modelTier: "medium",
	},
	"authz-screen": {
		name: "authz-screen",
		displayName: "Authz screen agent",
		prerequisites: ["authz-vuln"],
		promptTemplate: "screen-authz",
		deliverableFilename: "authz_screened_queue.json",
		modelTier: "medium",
	},
	"logic-screen": {
		name: "logic-screen",
		displayName: "Logic screen agent",
		prerequisites: ["logic-vuln"],
		promptTemplate: "screen-logic",
		deliverableFilename: "logic_screened_queue.json",
		modelTier: "medium",
	},
	"misconfig-web-screen": {
		name: "misconfig-web-screen",
		displayName: "Web misconfig screen agent",
		prerequisites: ["misconfig-web-vuln"],
		promptTemplate: "screen-misconfig-web",
		deliverableFilename: "misconfig-web_screened_queue.json",
		modelTier: "medium",
	},
});

export const screenValidators: Record<
	Extract<AgentName, `${string}-screen`>,
	AgentValidator
> = Object.freeze({
	"injection-screen": createScreenValidator("injection"),
	"xss-screen": createScreenValidator("xss"),
	"auth-screen": createScreenValidator("auth"),
	"ssrf-screen": createScreenValidator("ssrf"),
	"authz-screen": createScreenValidator("authz"),
	"logic-screen": createNewCategoryScreenValidator("logic_screened_queue.json"),
	"misconfig-web-screen": createNewCategoryScreenValidator(
		"misconfig-web_screened_queue.json",
	),
});
