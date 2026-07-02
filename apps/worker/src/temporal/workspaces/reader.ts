// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import fs from "node:fs/promises";
import path from "node:path";
import type { SessionJson, WorkspaceInfo } from "./types.js";

/** Try to read a workspace from a directory. Returns null if no valid session.json. */
export async function readWorkspace(
	baseDir: string,
	name: string,
): Promise<WorkspaceInfo | null> {
	const sessionPath = path.join(baseDir, name, "session.json");
	try {
		const content = await fs.readFile(sessionPath, "utf8");
		const data = JSON.parse(content) as SessionJson;
		return {
			name,
			url: data.session.webUrl,
			status: data.session.status,
			createdAt: new Date(data.session.createdAt),
			completedAt: data.session.completedAt
				? new Date(data.session.completedAt)
				: null,
		};
	} catch {
		return null;
	}
}

/**
 * Walk `workspacesDir`, descending one level into category directories,
 * and collect every directory that contains a parseable `session.json`.
 */
export async function collectWorkspaces(
	workspacesDir: string,
): Promise<WorkspaceInfo[]> {
	let entries: string[];
	try {
		entries = await fs.readdir(workspacesDir);
	} catch {
		return [];
	}

	const workspaces: WorkspaceInfo[] = [];

	for (const entry of entries) {
		// Skip hidden dirs, files, and category dirs — scan inside for session.json
		if (entry.startsWith(".")) continue;

		const fullPath = path.join(workspacesDir, entry);
		const stat = await fs.stat(fullPath).catch(() => null);
		if (!stat || !stat.isDirectory()) continue;

		// Could be a category dir (has subdirs) or a flat workspace. Check both:
		// 1. Is this itself a workspace? (has session.json)
		let selfSession: string | null = null;
		try {
			await fs.access(path.join(fullPath, "session.json"));
			selfSession = entry;
		} catch {
			// Not a flat workspace
		}

		if (selfSession) {
			const ws = await readWorkspace(workspacesDir, entry);
			if (ws) workspaces.push(ws);
		} else {
			// 2. It's a category dir — scan subdirectories
			let subEntries: string[];
			try {
				subEntries = await fs.readdir(fullPath);
			} catch {
				continue;
			}
			for (const sub of subEntries) {
				const ws = await readWorkspace(fullPath, sub);
				if (ws) workspaces.push(ws);
			}
		}
	}

	return workspaces;
}
