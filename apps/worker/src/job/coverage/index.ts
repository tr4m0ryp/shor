// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Public surface of the coverage module (T1 shared contract).
 *
 * Re-exports the `CoverageManifest` type, the `isTierCovered` helper, and the
 * deterministic classifier. Also provides the filesystem integration the
 * pre-recon stage uses: walk the cloned repo into a seed manifest, and
 * read/write `coverage_manifest.json` in the deliverables directory.
 */

import { fs, path } from "zx";

import { classifyPaths, parsePackageJsonHints } from "./classify.js";
import type { PackageJsonHints } from "./classify.js";
import {
	COVERAGE_MANIFEST_FILENAME,
	normalizeManifest,
} from "./manifest.js";
import type { CoverageManifest } from "./manifest.js";

export type {
	CoverageManifest,
	CoverageTier,
	TierPresence,
} from "./manifest.js";
export {
	COVERAGE_MANIFEST_FILENAME,
	COVERAGE_TIERS,
	isTierCovered,
	normalizeManifest,
} from "./manifest.js";
export type { PackageJsonHints } from "./classify.js";
export { classifyPaths, parsePackageJsonHints } from "./classify.js";

/** Directories never worth walking for tier classification. */
const SKIP_DIRS = new Set([
	".git",
	"node_modules",
	".storron",
	"dist",
	"build",
	".next",
	".nuxt",
	"vendor",
	"__pycache__",
	".venv",
	"venv",
	"target",
]);

/** Cap the walk so a pathological repo cannot stall pre-recon. */
const MAX_WALK_ENTRIES = 20_000;

/**
 * Recursively collect repo-relative POSIX paths under `repoPath`, skipping
 * build/vendor noise. Best-effort: unreadable directories are skipped. Exported
 * so the coverage census (`census.ts`) can reuse the same walk + skip rules.
 */
export async function collectRepoPaths(repoPath: string): Promise<string[]> {
	const out: string[] = [];
	const stack: string[] = [repoPath];

	while (stack.length > 0 && out.length < MAX_WALK_ENTRIES) {
		const dir = stack.pop();
		if (dir === undefined) break;
		let entries: import("node:fs").Dirent[];
		try {
			entries = await fs.readdir(dir, { withFileTypes: true });
		} catch {
			continue;
		}
		for (const entry of entries) {
			const abs = path.join(dir, entry.name);
			if (entry.isDirectory()) {
				if (SKIP_DIRS.has(entry.name)) continue;
				stack.push(abs);
			} else if (entry.isFile()) {
				const rel = path.relative(repoPath, abs).split(path.sep).join("/");
				out.push(rel);
				if (out.length >= MAX_WALK_ENTRIES) break;
			}
		}
	}
	return out;
}

/** Read + parse the root `package.json` (if any) into dependency hints. */
async function readPackageHints(
	repoPath: string,
): Promise<PackageJsonHints | undefined> {
	const pkgPath = path.join(repoPath, "package.json");
	try {
		if (!(await fs.pathExists(pkgPath))) return undefined;
		return parsePackageJsonHints(await fs.readFile(pkgPath, "utf8"));
	} catch {
		return undefined;
	}
}

/**
 * Build a seed `CoverageManifest` by walking the cloned repository. Returns
 * `undefined` when the repo path does not exist or holds no analyzable files
 * (a black-box scan), so callers can synthesize a no-repo manifest instead.
 */
export async function buildManifestFromRepo(
	repoPath: string,
): Promise<CoverageManifest | undefined> {
	if (!repoPath || !(await fs.pathExists(repoPath))) return undefined;
	const paths = await collectRepoPaths(repoPath);
	if (paths.length === 0) return undefined;
	const hints = await readPackageHints(repoPath);
	return classifyPaths(paths, hints);
}

/**
 * Write the manifest as `coverage_manifest.json` into `deliverablesDir`
 * (alongside `pre_recon_deliverable.md`). Ensures the directory exists.
 */
export async function writeManifest(
	deliverablesDir: string,
	manifest: CoverageManifest,
): Promise<string> {
	const file = path.join(deliverablesDir, COVERAGE_MANIFEST_FILENAME);
	await fs.ensureDir(deliverablesDir);
	await fs.writeFile(file, `${JSON.stringify(manifest, null, 2)}\n`);
	return file;
}

/**
 * Read + normalize `coverage_manifest.json` from `deliverablesDir`, or
 * `undefined` if it is absent/unparseable. Always returns a well-formed
 * manifest when defined (missing fields defaulted).
 */
export async function readManifest(
	deliverablesDir: string,
): Promise<CoverageManifest | undefined> {
	const file = path.join(deliverablesDir, COVERAGE_MANIFEST_FILENAME);
	try {
		if (!(await fs.pathExists(file))) return undefined;
		return normalizeManifest(JSON.parse(await fs.readFile(file, "utf8")));
	} catch {
		return undefined;
	}
}
