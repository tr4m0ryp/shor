// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
