// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import fs from "node:fs/promises";
import { WORKSPACES_DIR as DEFAULT_WORKSPACES_DIR } from "../../paths.js";
import { collectWorkspaces } from "./reader.js";
import { renderFooter, renderHeader, renderRow } from "./render.js";

/**
 * Entry-point for the `workspaces` CLI command.
 *
 * Reads the workspaces directory (overridable via `WORKSPACES_DIR`), parses
 * each `session.json`, and prints a formatted table sorted most-recent first.
 */
export async function listWorkspaces(): Promise<void> {
	const workspacesDir = process.env.WORKSPACES_DIR || DEFAULT_WORKSPACES_DIR;

	// Probe the directory once so we can show a friendly message when it is absent
	// before doing any deeper traversal.
	try {
		await fs.access(workspacesDir);
	} catch {
		console.log("No workspaces directory found.");
		console.log(`Expected: ${workspacesDir}`);
		return;
	}

	const workspaces = await collectWorkspaces(workspacesDir);

	if (workspaces.length === 0) {
		console.log("\nNo workspaces found.");
		console.log("Run a pipeline first: ./storron start -u <url> -r <repo>");
		return;
	}

	// Sort by creation date (most recent first)
	workspaces.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

	renderHeader();

	let resumableCount = 0;
	for (const ws of workspaces) {
		if (renderRow(ws)) {
			resumableCount++;
		}
	}

	renderFooter(workspaces.length, resumableCount);
}
