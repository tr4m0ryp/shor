// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * CheckpointProvider — injectable interface for external state persistence.
 *
 * Called after each agent completes to allow external progress tracking.
 * During the concurrent vulnerability-exploitation phase, 5 pipelines run
 * in parallel — onAgentComplete fires per-agent for granular progress.
 *
 * Default: no-op.
 */

import type { PipelineState } from "../temporal/shared.js";

export interface CheckpointProvider {
	onAgentComplete(
		agentName: string,
		phase: string,
		state: PipelineState,
	): Promise<void>;
}

/** Default no-op implementation — no external checkpointing. */
export class NoOpCheckpointProvider implements CheckpointProvider {
	async onAgentComplete(): Promise<void> {
		// No-op
	}
}
