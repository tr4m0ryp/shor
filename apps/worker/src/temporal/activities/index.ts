// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Temporal activities for Storron agent execution.
 *
 * Each activity wraps service calls with Temporal-specific concerns:
 * - Heartbeat loop (2s interval) to signal worker liveness
 * - Error classification into ApplicationFailure
 * - Container lifecycle management
 *
 * Business logic is delegated to services in src/services/. This barrel
 * re-exports every public activity so `proxyActivities<typeof activities>`
 * keeps inferring the full surface.
 */

export {
	runAttackSurfaceAgent,
	runAuthExploitAgent,
	runAuthVulnAgent,
	runAuthzExploitAgent,
	runAuthzVulnAgent,
	runInjectionExploitAgent,
	runInjectionVulnAgent,
	runPreReconAgent,
	runReconAgent,
	runReportAgent,
	runSsrfExploitAgent,
	runSsrfVulnAgent,
	runXssExploitAgent,
	runXssVulnAgent,
} from "./agents/dispatchers.js";
export {
	resolveReconCandidates,
	runReconToolSubrun,
} from "./agents/recon-fanout.js";
export {
	logPhaseTransition,
	logWorkflowComplete,
	saveCheckpoint,
} from "./audit-logging.js";
export { restoreGitCheckpoint } from "./git/checkpoint-restore.js";

export { initDeliverableGit } from "./git/init-deliverable.js";
export { runPreflightValidation } from "./preflight.js";
export { checkExploitationQueue, mergeFindingsIntoQueue } from "./queue.js";
export {
	assembleReportActivity,
	injectReportMetadataActivity,
} from "./reporting.js";

export { loadResumeState } from "./resume/load-state.js";
export { recordResumeAttempt } from "./resume/record-attempt.js";
export type { ActivityInput } from "./types.js";
