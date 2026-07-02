// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Record a resume attempt onto the existing audit session.
 *
 * Appends the attempt metadata to session.json and writes a resume header
 * to workflow.log so subsequent runs can be traced back to the previous one.
 */

import { AuditSession } from "../../../audit/index.js";
import { buildSessionMetadata } from "../_internal.js";
import type { ActivityInput } from "../types.js";

/**
 * Record a resume attempt in session.json and write resume header to workflow.log.
 */
export async function recordResumeAttempt(
	input: ActivityInput,
	terminatedWorkflows: string[],
	checkpointHash: string,
	previousWorkflowId: string,
	completedAgents: string[],
): Promise<void> {
	const sessionMetadata = buildSessionMetadata(input);
	const auditSession = new AuditSession(sessionMetadata);
	await auditSession.initialize();

	// Update session.json with resume attempt
	await auditSession.addResumeAttempt(
		input.workflowId,
		terminatedWorkflows,
		checkpointHash,
	);

	// Write resume header to workflow.log
	await auditSession.logResumeHeader({
		previousWorkflowId,
		newWorkflowId: input.workflowId,
		checkpointHash,
		completedAgents,
	});
}
