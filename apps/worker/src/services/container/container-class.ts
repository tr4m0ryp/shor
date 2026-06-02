// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Per-workflow DI Container.
 *
 * Holds all service instances for the workflow lifecycle, wired with explicit
 * constructor injection. AuditSession is intentionally excluded; each agent
 * execution receives its own AuditSession instance because AuditSession uses
 * per-agent instance state that cannot be shared across parallel agents.
 *
 * Network egress is clearnet-only; the former Tor readiness hooks
 * (`ensureTorReady` / `closeTor`) are retained as no-ops for interface
 * stability with callers that still invoke them in the workflow lifecycle.
 */

import type { SessionMetadata } from "../../audit/utils.js";
import type { CheckpointProvider } from "../../interfaces/checkpoint-provider.js";
import { NoOpCheckpointProvider } from "../../interfaces/checkpoint-provider.js";
import type { FindingsProvider } from "../../interfaces/findings-provider.js";
import { NoOpFindingsProvider } from "../../interfaces/findings-provider.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { ContainerConfig } from "../../types/config.js";
import type { ErrorCode } from "../../types/errors.js";
import { ok, type Result } from "../../types/result.js";
import { AgentExecutionService } from "../agent-execution.js";
import { ConfigLoaderService } from "../config-loader.js";
import { ExploitationCheckerService } from "../exploitation-checker.js";
import type { ContainerDependencies } from "./types.js";

/**
 * DI Container for a single workflow.
 *
 * Holds all service instances for the workflow lifecycle.
 * Services are instantiated once and reused across agent executions.
 *
 * NOTE: AuditSession is NOT stored here - it's passed per agent execution
 * to support parallel agents each having their own logging context.
 */
export class Container {
	readonly sessionMetadata: SessionMetadata;
	readonly config: ContainerConfig;
	readonly agentExecution: AgentExecutionService;
	readonly configLoader: ConfigLoaderService;
	readonly exploitationChecker: ExploitationCheckerService;
	readonly findingsProvider: FindingsProvider;
	readonly checkpointProvider: CheckpointProvider;

	constructor(deps: ContainerDependencies) {
		this.sessionMetadata = deps.sessionMetadata;
		this.config = deps.config;

		// Wire services with explicit constructor injection
		this.configLoader = new ConfigLoaderService();
		this.exploitationChecker = new ExploitationCheckerService();
		this.agentExecution = new AgentExecutionService(this.configLoader);

		// Wire providers with default no-ops when not provided
		this.findingsProvider = deps.findingsProvider ?? new NoOpFindingsProvider();
		this.checkpointProvider =
			deps.checkpointProvider ?? new NoOpCheckpointProvider();
	}

	/**
	 * No-op network readiness hook (clearnet-only build).
	 *
	 * Retained for interface stability; always resolves to `Ok(undefined)`.
	 */
	async ensureTorReady(
		_logger: ActivityLogger,
	): Promise<Result<undefined, ErrorCode>> {
		return ok(undefined);
	}

	/** No-op teardown hook (clearnet-only build). Idempotent. */
	closeTor(): void {
		// No network primitives to tear down.
	}
}
