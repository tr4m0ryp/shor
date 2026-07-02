// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Deterministic coverage census for the pre-recon stage.
 *
 * Pre-recon's lead agent decides which files its sub-agents read; nothing
 * verifies that decision, so a forgotten route handler is an *invisible* miss —
 * and pre-recon is the ONLY stage with full source access, so a source-level
 * miss is permanent. This module turns "assumed coverage" into "measured
 * coverage": enumerate the backend source files that exist in the clone, then
 * check which ones the agent actually cited in its deliverable. Whatever is
 * never cited is the audited blind spot downstream can be told to re-examine.
 *
 * Pure where it can be (`isBackendSourceFile`, `extractCitedPaths`,
 * `auditCoverage`) so the matching logic is trivially testable; only
 * `collectBackendSourceFiles` touches the filesystem.
 */

import { fs } from "zx";

import { BACKEND_EXTENSIONS, BACKEND_PATH_FRAGMENTS } from "./classify.js";
import { collectRepoPaths } from "./index.js";

/** Server entrypoints worth reviewing as source (manifests are excluded). */
const SERVER_ENTRYPOINTS = new Set([
	"server.js",
	"server.ts",
	"app.py",
	"wsgi.py",
	"asgi.py",
	"manage.py",
	"main.go",
]);

/** JS/TS extensions only count as backend when on a backend-shaped path. */
const JS_TS_EXTENSIONS = new Set([".ts", ".js", ".mjs", ".cjs"]);

const TEST_PATTERNS = [
	/\.(test|spec)\.[cm]?[jt]sx?$/,
	/(^|\/)test_[^/]+\.py$/,
	/_test\.(go|py|rb)$/,
];

function normalize(rel: string): string {
	return rel.replace(/\\/g, "/").toLowerCase();
}

function extname(pathLower: string): string {
	const base = pathLower.slice(pathLower.lastIndexOf("/") + 1);
	const dot = base.lastIndexOf(".");
	return dot === -1 ? "" : base.slice(dot);
}

/**
 * True when `relPath` is server-side application source a reviewer is expected
 * to open for sink/dataflow analysis. Tests, type declarations, build output,
 * and dependency manifests are excluded; frontend render files are out of scope
 * for this census (the highest-cost misses are backend handlers). Pure.
 */
export function isBackendSourceFile(relPath: string): boolean {
	const p = normalize(relPath);
	if (p === "") return false;
	if (TEST_PATTERNS.some((re) => re.test(p))) return false;
	if (
		p.endsWith(".d.ts") ||
		p.includes("/__tests__/") ||
		p.includes("/test/") ||
		p.includes("/tests/")
	) {
		return false;
	}

	const base = p.slice(p.lastIndexOf("/") + 1);
	const ext = extname(p);
	const guarded = `/${p}`;

	// Server-side language files (.cs/.py/.go/.rb/.php/.java/.kt) — always source.
	if (BACKEND_EXTENSIONS.has(ext)) return true;
	if (SERVER_ENTRYPOINTS.has(base)) return true;
	// JS/TS files only when they sit on a route/controller/handler/... path.
	if (
		JS_TS_EXTENSIONS.has(ext) &&
		BACKEND_PATH_FRAGMENTS.some((frag) => guarded.includes(frag))
	) {
		return true;
	}
	return false;
}

/** Liberal extraction of `path.ext[:line[:col]]` tokens cited in the report. */
const CITED_TOKEN_RE = /([A-Za-z0-9_.\-/\\]+\.[A-Za-z0-9]{1,6})(?::\d+){0,2}/g;

/**
 * Pull every file-path-looking token out of the deliverable text, normalized to
 * lowercase POSIX (line/col suffixes and a leading `./` stripped). Liberal by
 * design — spurious tokens are harmless because {@link auditCoverage} only ever
 * tests them against the real source-file set. Pure.
 */
export function extractCitedPaths(text: string): string[] {
	const out = new Set<string>();
	for (const m of text.matchAll(CITED_TOKEN_RE)) {
		const raw = m[1];
		if (!raw) continue;
		const token = normalize(raw).replace(/^\.\//, "");
		if (token.includes("/") || token.includes(".")) out.add(token);
	}
	return [...out];
}

export interface CoverageAudit {
	/** Backend source files found in the clone. */
	total: number;
	/** How many of those were cited somewhere in the deliverable. */
	covered: number;
	/** Repo-relative paths (original case) never cited — the audited blind spot. */
	uncovered: string[];
	/** covered / total, or 1 when there is no backend source to audit. */
	ratio: number;
}

function isCited(relLower: string, cited: Set<string>): boolean {
	if (cited.has(relLower)) return true;
	for (const c of cited) {
		// Conservative path-suffix match (either direction) — never basename-only,
		// so a shared filename cannot falsely mark a file as covered.
		if (relLower.endsWith(`/${c}`) || c.endsWith(`/${relLower}`)) return true;
	}
	return false;
}

/**
 * Audit which backend source files the deliverable actually references. Pure:
 * `sourceFiles` are repo-relative POSIX paths, `deliverableText` the report
 * body. Returns the covered count and the uncovered list (sorted by input).
 */
export function auditCoverage(
	sourceFiles: readonly string[],
	deliverableText: string,
): CoverageAudit {
	const cited = new Set(extractCitedPaths(deliverableText));
	const uncovered: string[] = [];
	let covered = 0;
	for (const rel of sourceFiles) {
		if (isCited(normalize(rel), cited)) covered++;
		else uncovered.push(rel);
	}
	const total = sourceFiles.length;
	return {
		total,
		covered,
		uncovered,
		ratio: total === 0 ? 1 : covered / total,
	};
}

/**
 * Walk the cloned repo and return the backend source files (repo-relative
 * POSIX, sorted). Reuses the coverage walker (shared SKIP_DIRS + walk cap).
 * Best-effort: a missing/empty repo yields an empty list.
 */
export async function collectBackendSourceFiles(
	repoPath: string,
): Promise<string[]> {
	if (!repoPath || !(await fs.pathExists(repoPath))) return [];
	const all = await collectRepoPaths(repoPath);
	return all.filter(isBackendSourceFile).sort();
}
