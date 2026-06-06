// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import { auditVulnFloor, buildVulnCoverage } from "./vuln-postcheck.js";

describe("auditVulnFloor", () => {
	it("floor met when semgrep left a trace", () => {
		const a = auditVulnFloor("Ran semgrep over the repo; 4 sinks.", "xss");
		expect(a.floorMet).toBe(true);
	});

	it("flags the floor when semgrep is absent (the silent-skip gap)", () => {
		const a = auditVulnFloor("Manual taint trace; nuclei sweep.", "auth");
		expect(a.floorMet).toBe(false);
	});

	it("injection expects osv-scanner; flags it when missing", () => {
		const a = auditVulnFloor("semgrep taint run completed.", "injection");
		expect(a.floorMet).toBe(true);
		expect(a.recommendedMissing).toContain("osv-scanner");
	});

	it("misconfig-web expects nuclei + httpx", () => {
		const present = auditVulnFloor(
			"semgrep + nuclei + httpx header checks done.",
			"misconfig-web",
		);
		expect(present.recommendedMissing).toEqual([]);
		const partial = auditVulnFloor("semgrep + httpx only.", "misconfig-web");
		expect(partial.recommendedMissing).toEqual(["nuclei"]);
		expect(partial.recommendedRun).toContain("httpx");
	});

	it("categories with no extras never report recommended gaps", () => {
		const a = auditVulnFloor("semgrep done.", "ssrf");
		expect(a.recommendedMissing).toEqual([]);
		expect(a.recommendedRun).toEqual([]);
	});
});

describe("buildVulnCoverage", () => {
	it("captures the verdict in a structured shape", () => {
		const cov = buildVulnCoverage(
			auditVulnFloor("manual only", "logic"),
		) as Record<string, unknown>;
		expect(cov).toMatchObject({ category: "logic", floorMet: false });
		expect(cov.recommendedMissing).toContain("httpx");
	});
});
