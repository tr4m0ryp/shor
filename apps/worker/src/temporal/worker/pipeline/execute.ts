// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import type { WorkflowHandle } from "@temporalio/client";
import type {
	PipelineInput,
	PipelineProgress,
	PipelineState,
} from "../../shared.js";

const PROGRESS_QUERY = "getProgress";

/**
 * Polls workflow progress on a 30s interval and awaits the final result.
 * Logs summary metrics on success and exits the process on failure.
 */
export async function waitForWorkflowResult(
	handle: WorkflowHandle<(input: PipelineInput) => Promise<PipelineState>>,
): Promise<void> {
	const progressInterval = setInterval(async () => {
		try {
			const progress = await handle.query<PipelineProgress>(PROGRESS_QUERY);
			const elapsed = Math.floor(progress.elapsedMs / 1000);
			console.log(
				`[${elapsed}s] Phase: ${progress.currentPhase || "unknown"} | Agent: ${progress.currentAgent || "none"} | Completed: ${progress.completedAgents.length}/13`,
			);
		} catch {
			// Workflow may have completed
		}
	}, 30000);

	try {
		const result = await handle.result();
		clearInterval(progressInterval);

		console.log("\nPipeline completed successfully!");
		if (result.summary) {
			console.log(
				`Duration: ${Math.floor(result.summary.totalDurationMs / 1000)}s`,
			);
			console.log(`Agents completed: ${result.summary.agentCount}`);
			console.log(`Total turns: ${result.summary.totalTurns}`);
		}
	} catch (error) {
		clearInterval(progressInterval);
		console.error("\nPipeline failed:", error);
		process.exit(1);
	}
}
