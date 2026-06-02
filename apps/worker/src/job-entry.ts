#!/usr/bin/env node

// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Cloud Run Job entrypoint — one process per scan (ADR-051).
 *
 * The control plane (Temporal workflow → `runJob`) launches THIS as the Job
 * container command. It reads the scan params from the environment, runs the
 * ported agent pipeline in-process for that scan, and exits: 0 on success,
 * non-zero on failure (so the Job execution is marked failed and the launching
 * Temporal activity surfaces it to the scan workflow). The worker no longer
 * self-submits a Temporal workflow.
 *
 * The selected provider key is file-mounted (AEGIS_PROVIDER_KEY_FILE) and read
 * at use time inside the engine (sdk-env.ts); it is never an env value here.
 */

import { readScanJobParams } from "./job/env.js";
import { ConsoleActivityLogger } from "./job/logger.js";
import { runScanPipeline } from "./job/pipeline.js";

export { readScanJobParams } from "./job/env.js";
export { runScanPipeline } from "./job/pipeline.js";

/** Parse env, run the pipeline, and report. Throws to signal a failed run. */
export async function runJob(): Promise<void> {
	const logger = new ConsoleActivityLogger();
	const params = readScanJobParams();

	logger.info("Scan job starting", {
		scanId: params.scanId,
		targetUrl: params.targetUrl,
		repoGcsUri: params.repoGcsUri,
	});

	const result = await runScanPipeline(params, logger);

	logger.info("Scan job completed", {
		scanId: result.scanId,
		agentCount: result.completedAgents.length,
	});
}

// Execute only when invoked directly as the Job command (not when imported).
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
	runJob().catch((err: unknown) => {
		console.error("Scan job failed:", err);
		process.exit(1);
	});
}
