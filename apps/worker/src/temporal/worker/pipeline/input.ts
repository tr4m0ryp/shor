// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { PipelineInput } from "../../shared.js";
import type { CliArgs } from "../cli-args.js";
import type { WorkspaceResolution } from "../workspace/resolve.js";
import type { LoadedConfig } from "./config.js";

/** Builds the PipelineInput payload from parsed CLI args, resolved workspace, and loaded config. */
export function buildPipelineInput(
	args: CliArgs,
	workspace: WorkspaceResolution,
	loaded: LoadedConfig,
): PipelineInput {
	// OPTIONAL recon breadth: resolved HERE (worker/Node scope, outside the
	// workflow sandbox) so the deterministic workflow only reads the boolean.
	// Default off — the key is omitted entirely unless explicitly enabled, so a
	// disabled run's input is byte-identical to today.
	const reconFanout = process.env.SHOR_RECON_FANOUT === "1";

	return {
		webUrl: args.webUrl,
		repoPath: args.repoPath,
		workflowId: workspace.workflowId,
		sessionId: workspace.sessionId,
		...(args.configPath && { configPath: args.configPath }),
		...(reconFanout && { reconFanout: true }),

		...(workspace.isResume &&
			args.resumeFromWorkspace && {
				resumeFromWorkspace: args.resumeFromWorkspace,
			}),
		...(workspace.terminatedWorkflows.length > 0 && {
			terminatedWorkflows: workspace.terminatedWorkflows,
		}),
		...(Object.keys(loaded.pipelineConfig).length > 0 && {
			pipelineConfig: loaded.pipelineConfig,
		}),
	};
}
