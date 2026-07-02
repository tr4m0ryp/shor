// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Resume state loader.
 *
 * Validates an existing workspace's session.json against the requested URL,
 * cross-checks each agent's success status against deliverables on disk,
 * and resolves the latest checkpoint commit to seed the workflow.
 */

import path from "node:path";
import { ApplicationFailure } from "@temporalio/activity";
import { deliverablesDir, workspaceDir } from "../../../paths.js";
import { AGENTS } from "../../../session-manager.js";
import { ALL_AGENTS } from "../../../types/agents.js";
import { fileExists, readJson } from "../../../utils/file-io.js";
import { createActivityLogger } from "../../activity-logger.js";
import type { ResumeState } from "../../shared.js";
import { findLatestCommit } from "../git/checkpoint-restore.js";
import type { SessionJson } from "./session-json.js";

/**
 * Load resume state from an existing workspace.
 */
export async function loadResumeState(
	workspaceName: string,
	expectedUrl: string,
	expectedRepoPath: string,
	deliverablesSubdir?: string,
): Promise<ResumeState> {
	// 1. Validate workspace exists
	const sessionPath = path.join(workspaceDir(workspaceName), "session.json");

	const exists = await fileExists(sessionPath);
	if (!exists) {
		throw ApplicationFailure.nonRetryable(
			`Workspace not found: ${workspaceName}\nExpected path: ${sessionPath}`,
			"WorkspaceNotFoundError",
		);
	}

	// 2. Parse session.json and validate URL match
	let session: SessionJson;
	try {
		session = await readJson<SessionJson>(sessionPath);
	} catch (error) {
		const errorMsg = error instanceof Error ? error.message : String(error);
		throw ApplicationFailure.nonRetryable(
			`Corrupted session.json in workspace ${workspaceName}: ${errorMsg}`,
			"CorruptedSessionError",
		);
	}

	if (session.session.webUrl !== expectedUrl) {
		throw ApplicationFailure.nonRetryable(
			`URL mismatch with workspace\n  Workspace URL: ${session.session.webUrl}\n  Provided URL:  ${expectedUrl}`,
			"URLMismatchError",
		);
	}

	// 3. Cross-check agent status with deliverables on disk
	const completedAgents: string[] = [];
	const agents = session.metrics.agents;

	for (const agentName of ALL_AGENTS) {
		const agentData = agents[agentName];
		if (!agentData || agentData.status !== "success") {
			continue;
		}

		const deliverableFilename = AGENTS[agentName].deliverableFilename;
		const deliverablePath = path.join(
			deliverablesDir(expectedRepoPath, deliverablesSubdir),
			deliverableFilename,
		);
		const deliverableExists = await fileExists(deliverablePath);

		if (!deliverableExists) {
			const logger = createActivityLogger();
			logger.warn(
				`Agent ${agentName} shows success but deliverable missing, will re-run`,
			);
			continue;
		}

		completedAgents.push(agentName);
	}

	// 4. Collect git checkpoints and validate at least one exists
	const checkpoints = completedAgents
		.map((name) => agents[name]?.checkpoint)
		.filter((hash): hash is string => hash != null);

	if (checkpoints.length === 0) {
		const successAgents = Object.entries(agents)
			.filter(([, data]) => data.status === "success")
			.map(([name]) => name);

		throw ApplicationFailure.nonRetryable(
			`Cannot resume workspace ${workspaceName}: ` +
				(successAgents.length > 0
					? `${successAgents.length} agent(s) show success in session.json (${successAgents.join(", ")}) ` +
						`but their deliverable files are missing from disk. ` +
						`Start a fresh run instead.`
					: `No agents completed successfully. Start a fresh run instead.`),
			"NoCheckpointsError",
		);
	}

	// 5. Find the most recent checkpoint commit
	const deliverablesPath = deliverablesDir(
		expectedRepoPath,
		deliverablesSubdir,
	);
	const checkpointHash = await findLatestCommit(deliverablesPath, checkpoints);
	const originalWorkflowId =
		session.session.originalWorkflowId || session.session.id;

	// 6. Log summary and return resume state
	const logger = createActivityLogger();
	logger.info("Resume state loaded", {
		workspace: workspaceName,
		completedAgents: completedAgents.length,
		checkpoint: checkpointHash,
	});

	return {
		workspaceName,
		originalUrl: session.session.webUrl,
		completedAgents,
		checkpointHash,
		originalWorkflowId,
	};
}
