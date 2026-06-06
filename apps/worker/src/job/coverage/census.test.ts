// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import {
	auditCoverage,
	extractCitedPaths,
	isBackendSourceFile,
} from "./census.js";

describe("isBackendSourceFile", () => {
	it("counts server-side language files", () => {
		expect(isBackendSourceFile("Services/EffectService.cs")).toBe(true);
		expect(isBackendSourceFile("app/handlers/users.py")).toBe(true);
		expect(isBackendSourceFile("cmd/server/main.go")).toBe(true);
		expect(isBackendSourceFile("src/Auth.java")).toBe(true);
	});

	it("counts JS/TS only on backend-shaped paths", () => {
		expect(isBackendSourceFile("src/routes/users.ts")).toBe(true);
		expect(isBackendSourceFile("src/controllers/auth.js")).toBe(true);
		expect(isBackendSourceFile("src/utils/format.ts")).toBe(false);
	});

	it("counts known server entrypoints by basename", () => {
		expect(isBackendSourceFile("server.ts")).toBe(true);
		expect(isBackendSourceFile("manage.py")).toBe(true);
	});

	it("excludes tests, type decls, and frontend render files", () => {
		expect(isBackendSourceFile("src/routes/users.test.ts")).toBe(false);
		expect(isBackendSourceFile("tests/test_views.py")).toBe(false);
		expect(isBackendSourceFile("api_test.go")).toBe(false);
		expect(isBackendSourceFile("src/types/api.d.ts")).toBe(false);
		expect(isBackendSourceFile("src/components/Header.tsx")).toBe(false);
	});

	it("excludes manifests and config", () => {
		expect(isBackendSourceFile("package.json")).toBe(false);
		expect(isBackendSourceFile("go.mod")).toBe(false);
		expect(isBackendSourceFile("Dockerfile")).toBe(false);
		expect(isBackendSourceFile("db/schema.sql")).toBe(false);
	});

	it("normalizes backslash paths", () => {
		expect(isBackendSourceFile("src\\Services\\EffectService.cs")).toBe(true);
	});
});

describe("extractCitedPaths", () => {
	it("pulls path:line citations and strips line/col + case", () => {
		const cited = extractCitedPaths(
			"See `Services/EffectService.cs:211` and internal/handlers/user.go:142:5.",
		);
		expect(cited).toContain("services/effectservice.cs");
		expect(cited).toContain("internal/handlers/user.go");
	});

	it("strips a leading ./", () => {
		expect(extractCitedPaths("./src/routes/a.ts:1")).toContain(
			"src/routes/a.ts",
		);
	});
});

describe("auditCoverage", () => {
	const files = [
		"Services/EffectService.cs",
		"Controllers/AuthController.cs",
		"Models/User.cs",
	];

	it("matches a cited file by path suffix", () => {
		const text = "Vuln in `src/Services/EffectService.cs:211` (SSRF).";
		const audit = auditCoverage(files, text);
		expect(audit.covered).toBe(1);
		expect(audit.uncovered).toEqual([
			"Controllers/AuthController.cs",
			"Models/User.cs",
		]);
	});

	it("does not falsely cover on a shared basename", () => {
		// A different `User.cs` elsewhere must not mark Models/User.cs covered.
		const audit = auditCoverage(["Models/User.cs"], "see `Dto/User.cs:3`");
		expect(audit.covered).toBe(0);
	});

	it("ratio is 1 when there is no backend source to audit", () => {
		const audit = auditCoverage([], "anything");
		expect(audit.total).toBe(0);
		expect(audit.ratio).toBe(1);
		expect(audit.uncovered).toEqual([]);
	});

	it("counts full coverage", () => {
		const text = files.map((f) => `\`${f}:1\``).join(" ");
		const audit = auditCoverage(files, text);
		expect(audit.covered).toBe(3);
		expect(audit.ratio).toBe(1);
	});
});
