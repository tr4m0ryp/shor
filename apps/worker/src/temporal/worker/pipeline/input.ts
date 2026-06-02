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
	return {
		webUrl: args.webUrl,
		repoPath: args.repoPath,
		workflowId: workspace.workflowId,
		sessionId: workspace.sessionId,
		...(args.configPath && { configPath: args.configPath }),

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
