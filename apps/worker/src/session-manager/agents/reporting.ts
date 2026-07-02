// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { fs, path } from "zx";

import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentDefinition, AgentValidator } from "../../types/index.js";

export const reportAgent: AgentDefinition = {
	name: "report",
	displayName: "Report agent",
	prerequisites: [
		"injection-exploit",
		"xss-exploit",
		"auth-exploit",
		"ssrf-exploit",
		"authz-exploit",
	],
	promptTemplate: "report-executive",
	deliverableFilename: "comprehensive_security_assessment_report.md",
	modelTier: "small",
};

/** Validates the executive report deliverable. */
export const reportValidator: AgentValidator = async (
	sourceDir: string,
	logger: ActivityLogger,
): Promise<boolean> => {
	const reportFile = path.join(
		sourceDir,
		"comprehensive_security_assessment_report.md",
	);

	const reportExists = await fs.pathExists(reportFile);

	if (!reportExists) {
		logger.error(
			"Missing required deliverable: comprehensive_security_assessment_report.md",
		);
	}

	return reportExists;
};
