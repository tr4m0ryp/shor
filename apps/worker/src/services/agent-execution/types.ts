// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
