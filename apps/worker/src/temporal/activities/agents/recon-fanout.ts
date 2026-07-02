// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * OPTIONAL recon fan-out activities (default OFF, gated by `reconFanout`).
 *
 * Structural breadth for the RECON phase: instead of one recon agent whose
 * tool breadth is enforced after the fact by the coverage gate, fan recon out
 * into one sub-run per recommended tool so coverage is guaranteed by
 * construction. These activities exist only to back that fan-out — the default
 * pipeline never calls them.
 *
 * Determinism note: the candidate tool list is resolved HERE (activity scope),
 * not inside the workflow, so the workflow only ever sees a recorded list and
 * stays replay-deterministic. `policyFor("recon").candidates` is the same pool
 * Task 001's coverage gate scores against — single source of truth, no drift.
 *
 * Isolation note: every sub-run writes into its own per-tool deliverables
 * subdir so N parallel recon runs never race on the shared
 * `recon_deliverable.md` or its git commit.
 *
 * KNOWN GAP (deliberate, see module commit / task report): consolidating the
 * per-tool deliverables back into the single canonical `recon_deliverable.md`
 * that downstream exploit prompts read is a follow-up synthesis step and is
 * intentionally NOT implemented here. The on-path is therefore experimental and
 * unreachable by default.
 */

import { ApplicationFailure } from "@temporalio/activity";
import { policyFor } from "../../../services/coverage/index.js";
import { DEFAULT_DELIVERABLES_SUBDIR } from "../../../paths.js";
import type { AgentMetrics } from "../../shared.js";
import type { ActivityInput } from "../types.js";
import { runAgentActivity } from "./execute.js";

/**
 * Resolve the recon fan-out tool set: the recon agent's coverage candidates.
 *
 * Returns a plain `string[]` (not the readonly pool) so it serializes cleanly
 * across the Temporal boundary. Empty when recon has no policy.
 */
export async function resolveReconCandidates(): Promise<string[]> {
	return [...(policyFor("recon")?.candidates ?? [])];
}

/** Reject tool names that could escape the deliverables tree as a path segment. */
function assertSafeToolSegment(tool: string): void {
	if (!/^[a-z0-9][a-z0-9._-]*$/i.test(tool)) {
		throw ApplicationFailure.nonRetryable(
			`Invalid recon fan-out tool name: ${JSON.stringify(tool)}`,
			"ConfigurationError",
		);
	}
}

/**
 * Run a single recon sub-run focused on one tool.
 *
 * Routes the sub-run's output to an isolated per-tool deliverables subdir so it
 * cannot clobber a sibling sub-run's files. Delegates to the shared recon
 * dispatch; the per-tool prompt scoping (steering the agent to exactly `tool`)
 * is a separate agent-execution concern not wired here.
 */
export async function runReconToolSubrun(
	input: ActivityInput,
	tool: string,
): Promise<AgentMetrics> {
	assertSafeToolSegment(tool);
	const base = input.deliverablesSubdir ?? DEFAULT_DELIVERABLES_SUBDIR;
	const subInput: ActivityInput = {
		...input,
		deliverablesSubdir: `${base}/recon/${tool}`,
	};
	return runAgentActivity("recon", subInput);
}
