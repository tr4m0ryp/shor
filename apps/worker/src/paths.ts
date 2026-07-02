// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/** Centralized path constants for the worker package */

import fs from "node:fs";
import path from "node:path";

/** Worker package root (apps/worker/) resolved from compiled dist/ files */
const WORKER_ROOT = path.resolve(import.meta.dirname, "..");

export const PROMPTS_DIR = path.join(WORKER_ROOT, "prompts");
export const CONFIGS_DIR = path.join(WORKER_ROOT, "configs");

/** Default deliverables subdirectory relative to repoPath */
export const DEFAULT_DELIVERABLES_SUBDIR = ".storron/deliverables";

/** Default audit log directory */
export const DEFAULT_AUDIT_DIR = "./workspaces";

/**
 * Resolve the deliverables directory for a given repoPath and optional subdir override.
 * @param repoPath - Absolute path to the target repository
 * @param subdir - Subdirectory relative to repoPath (default: '.storron/deliverables')
 */
export function deliverablesDir(
	repoPath: string,
	subdir: string = DEFAULT_DELIVERABLES_SUBDIR,
): string {
	return path.join(repoPath, ...subdir.split("/"));
}

/**
 * Repository root — walk up from WORKER_ROOT looking for pnpm-workspace.yaml.
 * Falls back to two levels up (apps/worker/ → repo root) if not found.
 */
function findRepoRoot(): string {
	let dir = WORKER_ROOT;
	for (let i = 0; i < 5; i++) {
		if (fs.existsSync(path.join(dir, "pnpm-workspace.yaml"))) {
			return dir;
		}
		const parent = path.dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}
	return path.resolve(WORKER_ROOT, "..", "..");
}

const REPO_ROOT = findRepoRoot();
export const WORKSPACES_DIR = path.join(REPO_ROOT, "workspaces");

/**
 * Extract category prefix from workspace name (everything before first `-`).
 * Workspaces without a hyphen go in `misc/`.
 */
export function workspaceCategory(name: string): string {
	const idx = name.indexOf("-");
	if (idx === -1) return "misc";
	return name.slice(0, idx);
}

/**
 * Resolve a workspace name to its nested directory path.
 * E.g., `web_bounty-hackerone-shopify-001` → `workspaces/web_bounty/web_bounty-hackerone-shopify-001/`
 */
export function workspaceDir(name: string): string {
	return path.join(WORKSPACES_DIR, workspaceCategory(name), name);
}
