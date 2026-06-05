// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Deterministic file-role/tier classifier (heuristic seed for the coverage
 * manifest). Pure over a list of repo-relative POSIX paths so it is trivially
 * testable; the pre-recon agent later confirms or overrides the seed.
 *
 * Heuristics are intentionally conservative — path/extension/framework markers
 * only, no file-content parsing. A marker raises a tier to `present`; weaker
 * signals raise it to at most `partial`. Backend is the load-bearing tier: when
 * the repo is a pure client bundle (React/Vue SPA, static HTML) with no server
 * framework or route handlers, `backend` stays `absent` — the signal task 003
 * uses to flag the unseen trust boundary behind a live API.
 */

import type { CoverageManifest, CoverageTier, TierPresence } from "./manifest.js";
import { COVERAGE_TIERS } from "./manifest.js";

/** Internal per-tier strength: 0 = absent, 1 = partial, 2 = present. */
type Strength = 0 | 1 | 2;

const STRENGTH_TO_PRESENCE: Record<Strength, TierPresence> = {
	0: "absent",
	1: "partial",
	2: "present",
};

/** Frontend framework/build markers in a `package.json` dependency blob. */
const FRONTEND_DEP_MARKERS = [
	"react", "react-dom", "vue", "@angular/core", "svelte", "next", "nuxt",
	"vite", "@vitejs/plugin-react", "solid-js", "preact",
];

/** Server-framework markers in a `package.json` dependency blob. */
const BACKEND_DEP_MARKERS = [
	"express", "fastify", "koa", "@nestjs/core", "hapi", "@hapi/hapi",
	"apollo-server", "@apollo/server", "hono", "restify", "sequelize",
	"typeorm", "prisma", "mongoose", "knex", "drizzle-orm", "pg", "mysql2",
];

/** Lowercased basenames that strongly imply a server entrypoint/runtime. */
const BACKEND_BASENAMES = new Set([
	"server.js", "server.ts", "app.py", "wsgi.py", "asgi.py", "manage.py",
	"main.go", "gemfile", "pom.xml", "build.gradle", "go.mod",
	"requirements.txt", "pipfile", "composer.json",
]);

/** Path fragments that imply server-side route/handler/model code. */
const BACKEND_PATH_FRAGMENTS = [
	"/routes/", "/controllers/", "/handlers/", "/api/", "/server/",
	"/models/", "/middleware/", "/services/", "/migrations/",
];

/** Server-side language extensions. */
const BACKEND_EXTENSIONS = new Set([
	".py", ".go", ".rb", ".php", ".java", ".kt", ".cs",
]);

/** Lowercased basenames that imply deployment/config. */
const CONFIG_BASENAMES = new Set([
	"dockerfile", "docker-compose.yml", "docker-compose.yaml", "nginx.conf",
	"makefile", "procfile", "vercel.json", "netlify.toml",
]);

function ext(pathLower: string): string {
	const slash = pathLower.lastIndexOf("/");
	const base = slash === -1 ? pathLower : pathLower.slice(slash + 1);
	const dot = base.lastIndexOf(".");
	return dot === -1 ? "" : base.slice(dot);
}

function basename(pathLower: string): string {
	const slash = pathLower.lastIndexOf("/");
	return slash === -1 ? pathLower : pathLower.slice(slash + 1);
}

function raise(
	scores: Record<CoverageTier, Strength>,
	tier: CoverageTier,
	to: Strength,
): void {
	if (to > scores[tier]) scores[tier] = to;
}

/** A `package.json` parsed into its merged dependency name set (best-effort). */
export interface PackageJsonHints {
	deps: Set<string>;
}

/**
 * Classify a single path, mutating the per-tier strength scores. `pkgHints`
 * (if supplied) sharpens the frontend/backend split using dependency markers
 * from a parsed root `package.json`.
 */
function classifyPath(
	rawPath: string,
	scores: Record<CoverageTier, Strength>,
	pkgHints: PackageJsonHints | undefined,
): void {
	const p = rawPath.replace(/\\/g, "/").toLowerCase();
	const base = basename(p);
	const extension = ext(p);
	// Leading-slash-normalized form so `/dir/` fragment tests match a top-level
	// directory too (repo-relative paths have no leading slash for root dirs).
	const guarded = `/${p}`;

	// --- tests (checked first; a test file is a test regardless of tier) ---
	if (
		guarded.includes("/__tests__/") ||
		guarded.includes("/test/") ||
		guarded.includes("/tests/") ||
		/\.(test|spec)\.[cm]?[jt]sx?$/.test(p) ||
		/(^|\/)test_[^/]+\.py$/.test(p) ||
		/_test\.(go|py|rb)$/.test(p)
	) {
		raise(scores, "tests", 2);
		return;
	}

	// --- schema ---
	if (
		extension === ".sql" ||
		base === "schema.prisma" ||
		base.endsWith(".graphql") ||
		base.endsWith(".gql") ||
		base.endsWith(".proto") ||
		base.endsWith(".schema.json") ||
		guarded.includes("/migrations/")
	) {
		raise(scores, "schema", 2);
		// migrations also imply a backend persistence layer.
		if (guarded.includes("/migrations/")) raise(scores, "backend", 2);
		return;
	}

	// --- config / deployment ---
	if (
		CONFIG_BASENAMES.has(base) ||
		base.startsWith("dockerfile") ||
		base.startsWith(".env") ||
		extension === ".yaml" ||
		extension === ".yml" ||
		extension === ".toml" ||
		base === ".gitlab-ci.yml" ||
		guarded.includes("/.github/workflows/") ||
		guarded.includes("/k8s/") ||
		guarded.includes("/helm/")
	) {
		raise(scores, "config", 2);
		return;
	}

	// --- backend (strong basename / path markers) ---
	if (BACKEND_BASENAMES.has(base)) {
		raise(scores, "backend", 2);
		return;
	}
	// A backend-shaped path (routes/, controllers/, models/...) or a server-side
	// language extension is a strong server signal.
	if (
		BACKEND_PATH_FRAGMENTS.some((frag) => guarded.includes(frag)) ||
		BACKEND_EXTENSIONS.has(extension)
	) {
		raise(scores, "backend", 2);
	}

	// --- frontend ---
	if (
		extension === ".tsx" ||
		extension === ".jsx" ||
		extension === ".vue" ||
		extension === ".svelte" ||
		base === "index.html" ||
		extension === ".html" ||
		extension === ".css" ||
		extension === ".scss"
	) {
		raise(scores, "frontend", 2);
		return;
	}
	if (
		guarded.includes("/components/") ||
		guarded.includes("/public/") ||
		guarded.includes("/assets/")
	) {
		raise(scores, "frontend", 1);
	}

	// --- package.json: split by dependency markers ---
	if (base === "package.json") {
		raise(scores, "frontend", 1); // a JS project at least ships a client toolchain
		if (pkgHints) {
			if (FRONTEND_DEP_MARKERS.some((d) => pkgHints.deps.has(d))) {
				raise(scores, "frontend", 2);
			}
			if (BACKEND_DEP_MARKERS.some((d) => pkgHints.deps.has(d))) {
				raise(scores, "backend", 2);
			}
		}
	}
}

/**
 * Build a seed `CoverageManifest` from repo-relative paths. The result is a
 * deterministic heuristic the pre-recon agent later confirms or overrides.
 */
export function classifyPaths(
	paths: readonly string[],
	pkgHints?: PackageJsonHints,
): CoverageManifest {
	const scores: Record<CoverageTier, Strength> = {
		frontend: 0,
		backend: 0,
		config: 0,
		schema: 0,
		tests: 0,
	};

	for (const path of paths) {
		if (path.trim() === "") continue;
		classifyPath(path, scores, pkgHints);
	}

	const tiers = {} as Record<CoverageTier, TierPresence>;
	for (const tier of COVERAGE_TIERS) {
		tiers[tier] = STRENGTH_TO_PRESENCE[scores[tier]];
	}

	return {
		tiers,
		observedLiveOnly: [],
		notes: buildSeedNotes(tiers),
	};
}

/** Parse a root `package.json` body into merged dependency-name hints. */
export function parsePackageJsonHints(body: string): PackageJsonHints {
	const deps = new Set<string>();
	try {
		const json = JSON.parse(body) as Record<string, unknown>;
		for (const key of [
			"dependencies",
			"devDependencies",
			"peerDependencies",
			"optionalDependencies",
		]) {
			const block = json[key];
			if (block && typeof block === "object") {
				for (const name of Object.keys(block as Record<string, unknown>)) {
					deps.add(name.toLowerCase());
				}
			}
		}
	} catch {
		// Malformed package.json — fall back to path-only heuristics.
	}
	return { deps };
}

function buildSeedNotes(tiers: Record<CoverageTier, TierPresence>): string {
	if (tiers.frontend !== "absent" && tiers.backend === "absent") {
		return (
			"Heuristic seed: repository classifies as client-tier only (frontend " +
			"present, no server framework/route handlers/ORM detected). Any live " +
			"backend reachable from the target is an UNSEEN trust boundary — its " +
			"source is not in this upload."
		);
	}
	if (tiers.frontend === "absent" && tiers.backend !== "absent") {
		return "Heuristic seed: repository classifies as backend/service code; no client tier detected in source.";
	}
	return "Heuristic seed from deterministic file-role classification (pre-recon agent confirms or overrides).";
}
