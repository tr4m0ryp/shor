// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Final-report assembly and metadata injection activities.
 */

import path from "node:path";
import { workspaceDir } from "../../paths.js";
import {
	assembleFinalReport,
	injectModelIntoReport,
} from "../../services/reporting.js";
import { createActivityLogger } from "../activity-logger.js";
import type { ActivityInput } from "./types.js";

/**
 * Assemble the final report by concatenating exploitation evidence files.
 */
export async function assembleReportActivity(
	input: ActivityInput,
): Promise<void> {
	const { repoPath } = input;
	const logger = createActivityLogger();
	logger.info("Assembling deliverables from specialist agents...");
	try {
		await assembleFinalReport(repoPath, logger);
	} catch (error) {
		const err = error as Error;
		logger.warn(`Error assembling final report: ${err.message}`);
	}
}

/**
 * Inject model metadata into the final report.
 */
export async function injectReportMetadataActivity(
	input: ActivityInput,
): Promise<void> {
	const { repoPath, sessionId, outputPath } = input;
	const logger = createActivityLogger();
	const effectiveOutputPath = outputPath
		? path.join(outputPath, sessionId)
		: workspaceDir(sessionId);
	try {
		await injectModelIntoReport(repoPath, effectiveOutputPath, logger);
	} catch (error) {
		const err = error as Error;
		logger.warn(`Error injecting model into report: ${err.message}`);
	}
}
