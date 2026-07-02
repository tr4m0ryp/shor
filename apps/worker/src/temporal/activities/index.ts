// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
