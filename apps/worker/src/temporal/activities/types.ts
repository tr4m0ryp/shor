// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Public input/output types shared across Storron activities.
 */

import type { ProviderConfig } from "../../types/config.js";

/**
 * Input for all agent activities.
 *
 * Config fields are optional with sensible defaults. When provided, they
 * flow through to getOrCreateContainer() for path and credential configuration.
 */
export interface ActivityInput {
	webUrl: string;
	repoPath: string;
	configPath?: string;
	outputPath?: string;
	workflowId: string;
	sessionId: string;

	// Config fields — serializable, read by getOrCreateContainer()
	configYAML?: string;
	apiKey?: string;
	deliverablesSubdir?: string;
	auditDir?: string;
	promptDir?: string;
	sastSarifPath?: string;
	skipGitCheck?: boolean;
	providerConfig?: ProviderConfig;
}
