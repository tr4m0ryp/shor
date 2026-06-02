// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Combined Temporal worker + client for Storron pentest pipeline.
 *
 * Starts a worker on a per-invocation task queue, submits a workflow,
 * waits for the result, and exits. Designed to run as a single ephemeral
 * container per scan.
 *
 * Usage:
 *   node dist/temporal/worker.js <webUrl> <repoPath> [options]
 *
 * Options:
 *   --task-queue <name>    Task queue name (required, unique per scan)
 *   --config <path>        Configuration file path
 *   --output <path>        Output directory for workspaces
 *   --workspace <name>     Resume from existing workspace
 *   --pipeline-testing     Use minimal prompts for fast testing
 *
 * Environment:
 *   TEMPORAL_ADDRESS - Temporal server address (default: localhost:7233)
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client, Connection } from "@temporalio/client";
import {
	bundleWorkflowCode,
	NativeConnection,
	Worker,
} from "@temporalio/worker";
import * as activities from "../activities.js";
import type { PipelineInput, PipelineState } from "../shared.js";
import { type CliArgs, parseCliArgs } from "./cli-args.js";
import { loadPipelineConfig } from "./pipeline/config.js";
import { waitForWorkflowResult } from "./pipeline/execute.js";
import { buildPipelineInput } from "./pipeline/input.js";
import { copyDeliverables } from "./post-processing.js";
import { resolveWorkspace } from "./workspace/resolve.js";

export type { CliArgs };

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Main worker entry point: parses args, starts the worker, submits the workflow, waits, and cleans up. */
export async function run(): Promise<void> {
	// 1. Parse CLI args
	const args = parseCliArgs(process.argv.slice(2));

	// 2. Connect to Temporal server
	const address = process.env.TEMPORAL_ADDRESS || "localhost:7233";
	console.log(`Connecting to Temporal at ${address}...`);

	const connection = await NativeConnection.connect({ address });
	const clientConnection = await Connection.connect({ address });
	const client = new Client({ connection: clientConnection });

	try {
		// 3. Bundle workflows and create worker on per-invocation task queue
		console.log("Bundling workflows...");
		const workflowBundle = await bundleWorkflowCode({
			workflowsPath: path.join(__dirname, "..", "workflows.js"),
		});

		const worker = await Worker.create({
			connection,
			namespace: "default",
			workflowBundle,
			activities,
			taskQueue: args.taskQueue,
			maxConcurrentActivityTaskExecutions: 25,
		});

		// 4. Resolve workspace and build pipeline input
		const workspace = await resolveWorkspace(client, args);
		const loadedConfig = await loadPipelineConfig(args.configPath);
		const input = buildPipelineInput(args, workspace, loadedConfig);

		// 5. Start worker polling in the background
		const workerDone = worker.run();

		// 6. Submit workflow to the same task queue
		const handle = await client.workflow.start<
			(input: PipelineInput) => Promise<PipelineState>
		>("pentestPipelineWorkflow", {
			taskQueue: args.taskQueue,
			workflowId: workspace.workflowId,
			args: [input],
		});

		// 7. Wait for workflow result
		await waitForWorkflowResult(handle);

		// 8. Copy deliverables to output directory
		if (args.outputPath) {
			copyDeliverables(args.repoPath, args.outputPath);
		}

		// 9. Shut down worker gracefully
		worker.shutdown();
		await workerDone;
	} finally {
		await connection.close();
		await clientConnection.close();
	}
}
