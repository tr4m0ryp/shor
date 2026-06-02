// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
