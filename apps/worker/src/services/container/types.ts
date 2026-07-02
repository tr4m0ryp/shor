// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Container type definitions and runtime defaults.
 *
 * `ContainerDependencies` is the constructor input for `Container`.
 * `DEFAULT_CONFIG` is the OSS standalone runtime config used when no explicit
 * config is supplied.
 */

import type { SessionMetadata } from "../../audit/utils.js";
import type { CheckpointProvider } from "../../interfaces/checkpoint-provider.js";
import type { FindingsProvider } from "../../interfaces/findings-provider.js";
import type { ContainerConfig } from "../../types/config.js";

/**
 * Dependencies required to create a Container.
 *
 * NOTE: AuditSession is NOT stored in the container.
 * Each agent execution receives its own AuditSession instance
 * because AuditSession uses instance state (currentAgentName) that
 * cannot be shared across parallel agents.
 */
export interface ContainerDependencies {
	readonly sessionMetadata: SessionMetadata;
	readonly config: ContainerConfig;
	readonly findingsProvider?: FindingsProvider;
	readonly checkpointProvider?: CheckpointProvider;
}

/** Default container config -- OSS standalone defaults */
export const DEFAULT_CONFIG: ContainerConfig = {
	deliverablesSubdir: ".storron/deliverables",
	auditDir: "./workspaces",
};
