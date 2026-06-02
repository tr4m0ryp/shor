// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import path from "node:path";
import { type Client, WorkflowNotFoundError } from "@temporalio/client";
import { sanitizeHostname } from "../../../audit/utils.js";
import { workspaceDir } from "../../../paths.js";
import { fileExists, readJson } from "../../../utils/file-io.js";
import type { CliArgs } from "../cli-args.js";
import { isValidWorkspaceName } from "./name-validation.js";

export interface SessionJson {
	session: {
		id: string;
		webUrl: string;
		originalWorkflowId?: string;
		resumeAttempts?: Array<{ workflowId: string }>;
	};
}

export interface WorkspaceResolution {
	workflowId: string;
	sessionId: string;
	isResume: boolean;
	terminatedWorkflows: string[];
}

/** Terminates any RUNNING workflows recorded in the workspace's session.json. */
export async function terminateExistingWorkflows(
	client: Client,
	workspaceName: string,
): Promise<string[]> {
	const sessionPath = path.join(workspaceDir(workspaceName), "session.json");

	if (!(await fileExists(sessionPath))) {
		throw new Error(
			`Workspace not found: ${workspaceName}\n` +
				`Expected path: ${sessionPath}`,
		);
	}

	const session = await readJson<SessionJson>(sessionPath);

	const workflowIds = [
		session.session.originalWorkflowId || session.session.id,
		...(session.session.resumeAttempts?.map((r) => r.workflowId) || []),
	].filter((id): id is string => id != null);

	const terminated: string[] = [];

	for (const wfId of workflowIds) {
		try {
			const handle = client.workflow.getHandle(wfId);
			const description = await handle.describe();

			if (description.status.name === "RUNNING") {
				console.log(`Terminating running workflow: ${wfId}`);
				await handle.terminate("Superseded by resume workflow");
				terminated.push(wfId);
				console.log(`Terminated: ${wfId}`);
			} else {
				console.log(`Workflow already ${description.status.name}: ${wfId}`);
			}
		} catch (error) {
			if (error instanceof WorkflowNotFoundError) {
				console.log(`Workflow not found (already cleaned up): ${wfId}`);
			} else {
				console.log(`Failed to terminate ${wfId}: ${error}`);
			}
		}
	}

	return terminated;
}

/** Resolves the workspace for this run, including resume vs. new and ID generation. */
export async function resolveWorkspace(
	client: Client,
	args: CliArgs,
): Promise<WorkspaceResolution> {
	if (!args.resumeFromWorkspace) {
		const hostname = sanitizeHostname(args.webUrl);
		const workflowId = `${hostname}_storron-${Date.now()}`;
		return {
			workflowId,
			sessionId: workflowId,
			isResume: false,
			terminatedWorkflows: [],
		};
	}

	const workspace = args.resumeFromWorkspace;
	const sessionPath = path.join(workspaceDir(workspace), "session.json");
	const workspaceExists = await fileExists(sessionPath);

	if (workspaceExists) {
		console.log("=== RESUME MODE ===");
		console.log(`Workspace: ${workspace}\n`);

		const terminatedWorkflows = await terminateExistingWorkflows(
			client,
			workspace,
		);
		if (terminatedWorkflows.length > 0) {
			console.log(
				`Terminated ${terminatedWorkflows.length} previous workflow(s)\n`,
			);
		}

		const session = await readJson<SessionJson>(sessionPath);
		if (session.session.webUrl !== args.webUrl) {
			console.error("ERROR: URL mismatch with workspace");
			console.error(`  Workspace URL: ${session.session.webUrl}`);
			console.error(`  Provided URL:  ${args.webUrl}`);
			process.exit(1);
		}

		return {
			workflowId: `${workspace}_resume_${Date.now()}`,
			sessionId: workspace,
			isResume: true,
			terminatedWorkflows,
		};
	}

	if (!isValidWorkspaceName(workspace)) {
		console.error(`ERROR: Invalid workspace name: "${workspace}"`);
		console.error(
			"  Must be 1-128 characters, alphanumeric/hyphens/underscores, starting with alphanumeric",
		);
		process.exit(1);
	}

	console.log("=== NEW NAMED WORKSPACE ===");
	console.log(`Workspace: ${workspace}\n`);

	// If the workspace name already looks like a CLI-generated ID
	// (ends with _storron-<digits>), use it directly to avoid double _storron- suffixes
	const workflowId = /_storron-\d+$/.test(workspace)
		? workspace
		: `${workspace}_storron-${Date.now()}`;

	return {
		workflowId,
		sessionId: workspace,
		isResume: false,
		terminatedWorkflows: [],
	};
}
