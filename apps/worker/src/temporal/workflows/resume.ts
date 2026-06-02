// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Resume-handling for the Storron pentest workflow.
 *
 * Encapsulates the four-step resume protocol: load resume state from the
 * existing workspace, restore the git checkpoint while cleaning up
 * incomplete deliverables, short-circuit if every agent already finished,
 * and record the resume attempt for audit purposes.
 */

import { log } from "@temporalio/workflow";
import type { AgentName } from "../../types/agents.js";
import { ALL_AGENTS } from "../../types/agents.js";
import type { ResumeState } from "../shared.js";
import type { PipelineContext } from "./pipeline-context.js";
import { computeSummary } from "./state.js";

/** Outcome of attempting a resume. `shortCircuited === true` means every agent already ran. */
export interface ResumeOutcome {
	resumeState: ResumeState | null;
	shortCircuited: boolean;
}

/**
 * Execute the resume protocol when `resumeFromWorkspace` is set.
 *
 * 1. Load resume state (validates workspace, cross-checks deliverables)
 * 2. Restore git workspace and clean up incomplete deliverables
 * 3. Short-circuit if all agents already completed
 * 4. Record this resume attempt in session.json and workflow.log
 */
export async function maybeResume(
	ctx: PipelineContext,
): Promise<ResumeOutcome> {
	const { input, activityInput, state, a } = ctx;

	if (!input.resumeFromWorkspace) {
		return { resumeState: null, shortCircuited: false };
	}

	// 1. Load resume state (validates workspace, cross-checks deliverables)
	const resumeState = await a.loadResumeState(
		input.resumeFromWorkspace,
		input.webUrl,
		input.repoPath,
		input.deliverablesSubdir,
	);

	// 2. Restore git workspace and clean up incomplete deliverables
	const incompleteAgents = ALL_AGENTS.filter(
		(agentName) => !resumeState?.completedAgents.includes(agentName),
	) as AgentName[];

	await a.restoreGitCheckpoint(
		input.repoPath,
		resumeState.checkpointHash,
		incompleteAgents,
		input.deliverablesSubdir,
	);

	// 3. Short-circuit if all agents already completed
	if (resumeState.completedAgents.length === ALL_AGENTS.length) {
		log.info(
			`All ${ALL_AGENTS.length} agents already completed. Nothing to resume.`,
		);
		state.status = "completed";
		state.completedAgents = [...resumeState.completedAgents];
		state.summary = computeSummary(state);
		return { resumeState, shortCircuited: true };
	}

	// 4. Record this resume attempt in session.json and workflow.log
	await a.recordResumeAttempt(
		activityInput,
		input.terminatedWorkflows || [],
		resumeState.checkpointHash,
		resumeState.originalWorkflowId,
		resumeState.completedAgents,
	);

	log.info("Resume state loaded and workspace restored");
	return { resumeState, shortCircuited: false };
}
