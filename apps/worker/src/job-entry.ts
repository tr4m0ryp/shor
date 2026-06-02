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

import { assertNetworkAllowed } from "./guardrails/index.js";
import { readScanJobParams } from "./job/env.js";
import { reportFindings } from "./job/findings/index.js";
import { ConsoleActivityLogger } from "./job/logger.js";
import { runScanPipeline } from "./job/pipeline.js";
import { materializeRepo } from "./job/repo.js";
import { deliverablesDir } from "./paths.js";

export { readScanJobParams } from "./job/env.js";
export { runScanPipeline } from "./job/pipeline.js";

/** Parse env, run the pipeline, and report. Throws to signal a failed run. */
export async function runJob(): Promise<void> {
	const logger = new ConsoleActivityLogger();
	const params = readScanJobParams();

	// Guardrail (LAUNCH-SPEC §5.6): the scan target itself must clear the network
	// guard (RoE scope + egress allowlist, metadata/internal ranges blocked)
	// before the pipeline starts. The guard reads the run's RoE from AEGIS_ROE.
	// Per-tool/per-action calls are wired at integration; this is the gate at the
	// run boundary + the example call site for the engine.
	assertNetworkAllowed(params.targetUrl);

	logger.info("Scan job starting", {
		scanId: params.scanId,
		targetUrl: params.targetUrl,
		repoGcsUri: params.repoGcsUri,
	});

	// Phase 4 ingest: copy the GCS-mounted snapshot into the writable repoPath if
	// it is not already populated (no-op for the direct `docker run -v` case).
	await materializeRepo(params, logger);

	// Deliverables live under the repo; the pipeline writes them via the same
	// default subdir the container config uses (`.storron/deliverables`).
	const deliverablesPath = deliverablesDir(params.repoPath);

	try {
		const result = await runScanPipeline(params, logger);

		logger.info("Scan job completed", {
			scanId: result.scanId,
			agentCount: result.completedAgents.length,
		});

		// Post findings + attack surface to the dashboard sink (best-effort; a
		// failed POST is logged, never fatal).
		await reportFindings(deliverablesPath, params.scanId, "completed", logger);
	} catch (err) {
		// Pipeline failed: still emit a final `failed` status (with whatever
		// partial deliverables exist) so the dashboard does not hang on `running`.
		logger.error("Scan pipeline threw; reporting failed status", {
			scanId: params.scanId,
			error: err instanceof Error ? err.message : String(err),
		});
		await reportFindings(deliverablesPath, params.scanId, "failed", logger);
		throw err;
	}
}

// Execute only when invoked directly as the Job command (not when imported).
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
	runJob().catch((err: unknown) => {
		console.error("Scan job failed:", err);
		process.exit(1);
	});
}
