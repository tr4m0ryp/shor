// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import {
	EXPECTED_TOOLS,
	parseProbeOutput,
	summarizeToolHealth,
} from "./probe.js";

describe("parseProbeOutput", () => {
	it("marks resolved tools available and MISSING ones absent", () => {
		const stdout = [
			"semgrep\t/usr/local/bin/semgrep",
			"sqlmap\t/opt/tools/bin/sqlmap",
			"trufflehog\tMISSING",
		].join("\n");
		const probes = parseProbeOutput(stdout, ["semgrep", "sqlmap", "trufflehog"]);
		expect(probes).toEqual([
			{ tool: "semgrep", available: true, path: "/usr/local/bin/semgrep" },
			{ tool: "sqlmap", available: true, path: "/opt/tools/bin/sqlmap" },
			{ tool: "trufflehog", available: false, path: null },
		]);
	});

	it("treats a tool absent from the output as missing", () => {
		const probes = parseProbeOutput("semgrep\t/usr/bin/semgrep", [
			"semgrep",
			"nuclei",
		]);
		expect(probes[1]).toEqual({ tool: "nuclei", available: false, path: null });
	});

	it("treats an empty resolution as missing", () => {
		const probes = parseProbeOutput("ffuf\t", ["ffuf"]);
		expect(probes[0]?.available).toBe(false);
	});
});

describe("summarizeToolHealth", () => {
	it("counts available vs missing and lists the missing", () => {
		const summary = summarizeToolHealth([
			{ tool: "semgrep", available: true, path: "/x" },
			{ tool: "nuclei", available: true, path: "/y" },
			{ tool: "trufflehog", available: false, path: null },
		]);
		expect(summary.total).toBe(3);
		expect(summary.available).toBe(2);
		expect(summary.missing).toEqual(["trufflehog"]);
	});
});

describe("EXPECTED_TOOLS", () => {
	it("covers the core dynamic + static tools and excludes non-binary skills", () => {
		for (const t of ["semgrep", "sqlmap", "dalfox", "nuclei", "httpx"]) {
			expect(EXPECTED_TOOLS).toContain(t);
		}
		// Non-binary skills must NOT be probed as CLI tools.
		for (const skill of ["authz-recipe", "generate-totp", "playwright"]) {
			expect(EXPECTED_TOOLS).not.toContain(skill);
		}
	});
});
