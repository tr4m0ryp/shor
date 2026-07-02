// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { showUsage } from "./usage.js";

export interface CliArgs {
	webUrl: string;
	repoPath: string;
	taskQueue: string;
	configPath?: string;
	outputPath?: string;
	resumeFromWorkspace?: string;
}

/** Parses worker CLI arguments, exiting on help requests or missing required fields. */
export function parseCliArgs(argv: string[]): CliArgs {
	if (argv.includes("--help") || argv.includes("-h") || argv.length === 0) {
		showUsage();
		process.exit(0);
	}

	let webUrl: string | undefined;
	let repoPath: string | undefined;
	let taskQueue: string | undefined;
	let configPath: string | undefined;
	let outputPath: string | undefined;
	let resumeFromWorkspace: string | undefined;

	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i];
		if (arg === "--task-queue") {
			const nextArg = argv[i + 1];
			if (nextArg && !nextArg.startsWith("-")) {
				taskQueue = nextArg;
				i++;
			}
		} else if (arg === "--config") {
			const nextArg = argv[i + 1];
			if (nextArg && !nextArg.startsWith("-")) {
				configPath = nextArg;
				i++;
			}
		} else if (arg === "--output") {
			const nextArg = argv[i + 1];
			if (nextArg && !nextArg.startsWith("-")) {
				outputPath = nextArg;
				i++;
			}
		} else if (arg === "--workspace") {
			const nextArg = argv[i + 1];
			if (nextArg && !nextArg.startsWith("-")) {
				resumeFromWorkspace = nextArg;
				i++;
			}
		} else if (arg && !arg.startsWith("-")) {
			if (!webUrl) {
				webUrl = arg;
			} else if (!repoPath) {
				repoPath = arg;
			}
		}
	}

	if (!webUrl || !repoPath) {
		console.error("Error: webUrl and repoPath are required");
		showUsage();
		process.exit(1);
	}

	if (!taskQueue) {
		console.error("Error: --task-queue is required");
		showUsage();
		process.exit(1);
	}

	return {
		webUrl,
		repoPath,
		taskQueue,
		...(configPath && { configPath }),
		...(outputPath && { outputPath }),
		...(resumeFromWorkspace && { resumeFromWorkspace }),
	};
}
