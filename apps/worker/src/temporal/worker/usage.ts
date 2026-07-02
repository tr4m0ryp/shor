// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
