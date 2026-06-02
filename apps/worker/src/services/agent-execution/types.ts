// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Input types for agent execution.
 */

/**
 * Input for agent execution.
 */
export interface AgentExecutionInput {
	webUrl: string;
	repoPath: string;
	deliverablesPath: string;
	configPath?: string | undefined;
	configData?: import("../../types/config.js").DistributedConfig | undefined;
	configYAML?: string | undefined;
	pipelineTestingMode?: boolean | undefined;
	attemptNumber: number;
	apiKey?: string | undefined;
	promptDir?: string | undefined;
	providerConfig?: import("../../types/config.js").ProviderConfig | undefined;
}
