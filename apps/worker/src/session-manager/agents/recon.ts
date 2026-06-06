// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
