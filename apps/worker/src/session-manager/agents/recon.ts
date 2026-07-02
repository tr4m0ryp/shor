// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { fs, path } from "zx";

import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentDefinition, AgentValidator } from "../../types/index.js";
import { runReconPostChecks } from "./recon-postcheck.js";

const DELIVERABLE = "recon_deliverable.md";

export const reconAgent: AgentDefinition = {
	name: "recon",
	displayName: "Recon agent",
	prerequisites: ["pre-recon"],
	promptTemplate: "recon",
	deliverableFilename: DELIVERABLE,
};

/**
 * Validate the recon deliverable: it MUST exist, and — when it does — run the
 * deterministic tool-floor audit so a silently-skipped live-recon tool (e.g. a
 * never-run `nuclei`) is surfaced rather than passing as "done". The audit is
 * best-effort and never blocks; only a missing deliverable fails validation.
 */
export const reconValidator: AgentValidator = async (
	sourceDir: string,
	logger: ActivityLogger,
): Promise<boolean> => {
	const reconFile = path.join(sourceDir, DELIVERABLE);
	if (!(await fs.pathExists(reconFile))) return false;
	await runReconPostChecks(sourceDir, reconFile, logger);
	return true;
};
