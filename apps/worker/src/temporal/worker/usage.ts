// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/** Prints help text for the Storron worker CLI. */
export function showUsage(): void {
	console.log("\nStorron Worker");
	console.log("Combined worker + client for pentest pipeline\n");
	console.log("Usage:");
	console.log(
		"  node dist/temporal/worker.js <webUrl> <repoPath> --task-queue <name> [options]\n",
	);
	console.log("Options:");
	console.log("  --task-queue <name>    Task queue name (required)");
	console.log("  --config <path>        Configuration file path");
	console.log("  --workspace <name>     Resume from existing workspace\n");
}
