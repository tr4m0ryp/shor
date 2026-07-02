// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import { classifyPaths, parsePackageJsonHints } from "./classify.js";
import { isTierCovered } from "./manifest.js";

/** Minimal React SPA: client toolchain + components + index.html, no server. */
const REACT_SPA = [
	"package.json",
	"index.html",
	"vite.config.ts",
	"src/main.tsx",
	"src/App.tsx",
	"src/components/Header.tsx",
	"src/components/Footer.tsx",
	"src/styles/app.css",
	"public/favicon.svg",
];

const REACT_PKG = JSON.stringify({
	dependencies: { react: "^19.0.0", "react-dom": "^19.0.0" },
	devDependencies: { vite: "^5.0.0", typescript: "^5.0.0" },
});

const EXPRESS_PKG = JSON.stringify({
	dependencies: { express: "^4.19.0", pg: "^8.11.0" },
});

describe("classifyPaths — React SPA fixture", () => {
	it("frontend present, backend absent", () => {
		const manifest = classifyPaths(REACT_SPA, parsePackageJsonHints(REACT_PKG));
		expect(manifest.tiers.frontend).toBe("present");
		expect(manifest.tiers.backend).toBe("absent");
	});

	it("notes call out the unseen backend trust boundary", () => {
		const manifest = classifyPaths(REACT_SPA, parsePackageJsonHints(REACT_PKG));
		expect(manifest.notes.toLowerCase()).toContain("client-tier only");
		expect(manifest.notes.toLowerCase()).toContain("unseen trust boundary");
	});

	it("isTierCovered agrees with the verdict", () => {
		const manifest = classifyPaths(REACT_SPA, parsePackageJsonHints(REACT_PKG));
		expect(isTierCovered(manifest, "frontend")).toBe(true);
		expect(isTierCovered(manifest, "backend")).toBe(false);
	});

	it("observedLiveOnly seeds empty (filled later by the agent)", () => {
		const manifest = classifyPaths(REACT_SPA);
		expect(manifest.observedLiveOnly).toEqual([]);
	});
});

describe("classifyPaths — backend detection", () => {
	it("express deps in package.json mark backend present", () => {
		const manifest = classifyPaths(
			["package.json", "src/index.ts"],
			parsePackageJsonHints(EXPRESS_PKG),
		);
		expect(manifest.tiers.backend).toBe("present");
	});

	it("server-framework path fragments mark backend present", () => {
		const manifest = classifyPaths([
			"src/routes/users.ts",
			"src/controllers/auth.ts",
			"src/models/user.ts",
		]);
		expect(manifest.tiers.backend).toBe("present");
	});

	it("python/go source marks backend present", () => {
		expect(classifyPaths(["app.py", "lib/handler.py"]).tiers.backend).toBe(
			"present",
		);
		expect(classifyPaths(["cmd/main.go"]).tiers.backend).toBe("present");
	});
});

describe("classifyPaths — config / schema / tests", () => {
	it("Dockerfile and yaml mark config present", () => {
		expect(classifyPaths(["Dockerfile"]).tiers.config).toBe("present");
		expect(classifyPaths(["k8s/deploy.yaml"]).tiers.config).toBe("present");
		expect(classifyPaths([".env.production"]).tiers.config).toBe("present");
	});

	it("SQL / prisma / migrations mark schema present", () => {
		expect(classifyPaths(["db/schema.sql"]).tiers.schema).toBe("present");
		expect(classifyPaths(["prisma/schema.prisma"]).tiers.schema).toBe(
			"present",
		);
		const mig = classifyPaths(["migrations/001_init.sql"]);
		expect(mig.tiers.schema).toBe("present");
		// migrations also imply a backend persistence layer.
		expect(mig.tiers.backend).toBe("present");
	});

	it("test files mark tests present and win over tier classification", () => {
		expect(classifyPaths(["src/App.test.tsx"]).tiers.tests).toBe("present");
		expect(classifyPaths(["src/__tests__/util.ts"]).tiers.tests).toBe(
			"present",
		);
		expect(classifyPaths(["api_test.go"]).tiers.tests).toBe("present");
		expect(classifyPaths(["tests/test_views.py"]).tiers.tests).toBe("present");
	});
});

describe("classifyPaths — edge cases", () => {
	it("empty input yields all-absent manifest", () => {
		const manifest = classifyPaths([]);
		expect(manifest.tiers).toEqual({
			frontend: "absent",
			backend: "absent",
			config: "absent",
			schema: "absent",
			tests: "absent",
		});
	});

	it("blank path strings are ignored", () => {
		expect(classifyPaths(["", "   "]).tiers.frontend).toBe("absent");
	});

	it("malformed package.json degrades to path-only heuristics", () => {
		const hints = parsePackageJsonHints("{ not json");
		expect(hints.deps.size).toBe(0);
		// package.json alone (no parseable deps) is only a partial frontend hint.
		expect(classifyPaths(["package.json"], hints).tiers.frontend).toBe(
			"partial",
		);
	});

	it("backslash paths are normalized", () => {
		expect(classifyPaths(["src\\components\\Header.tsx"]).tiers.frontend).toBe(
			"present",
		);
	});
});
