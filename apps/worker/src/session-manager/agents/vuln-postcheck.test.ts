// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import {
	auditMutationEvidence,
	auditVulnFloor,
	buildVulnCoverage,
} from "./vuln-postcheck.js";

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

describe("auditMutationEvidence", () => {
	it("clean read-only deliverable is not suspected", () => {
		const m = auditMutationEvidence(
			"Reviewed the login flow; traced taint into the SQL sink. No writes performed.",
		);
		expect(m.suspected).toBe(false);
		expect(m.signals).toEqual([]);
	});

	it("flags an HTTP 201 Created … new user deliverable", () => {
		const m = auditMutationEvidence(
			"Forged an admin token and POSTed to /api/users — HTTP 201 Created, a new user landed in the DB.",
		);
		expect(m.suspected).toBe(true);
		expect(m.signals).toContain("201 created");
	});

	it("flags a poisoned MongoDB deliverable", () => {
		const m = auditMutationEvidence(
			"Inserted a malicious doc and poisoned the MongoDB users collection during analysis.",
		);
		expect(m.suspected).toBe(true);
		expect(m.signals).toEqual(expect.arrayContaining(["inserted", "poisoned"]));
	});

	it("a plain GET read does NOT trip it", () => {
		const m = auditMutationEvidence(
			"GET /Users read the directory listing; enumerated 12 accounts read-only.",
		);
		expect(m.suspected).toBe(false);
		expect(m.signals).toEqual([]);
	});

	it("a bare POST/PUT/DELETE without a create outcome does NOT trip it", () => {
		const m = auditMutationEvidence(
			"Sent a POST to /login and a DELETE to /session to probe the verb handling.",
		);
		expect(m.suspected).toBe(false);
		expect(m.signals).toEqual([]);
	});

	it("a write verb paired with a create outcome trips the paired rail", () => {
		const m = auditMutationEvidence(
			"Forged a token then PUT to /accounts which created a new account on the server.",
		);
		expect(m.suspected).toBe(true);
		expect(m.signals).toContain("write-verb paired with create/mutate outcome");
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

	it("defaults to no mutation evidence when none is supplied", () => {
		const cov = buildVulnCoverage(
			auditVulnFloor("semgrep done.", "xss"),
		) as Record<string, unknown>;
		expect(cov).toMatchObject({ mutationSuspected: false });
		expect(cov.mutationSignals).toEqual([]);
	});

	it("folds mutation evidence into the artifact", () => {
		const cov = buildVulnCoverage(
			auditVulnFloor("semgrep done.", "authz"),
			auditMutationEvidence("poisoned the records and inserted a row."),
		) as Record<string, unknown>;
		expect(cov).toMatchObject({ mutationSuspected: true });
		expect(cov.mutationSignals).toEqual(
			expect.arrayContaining(["poisoned", "inserted"]),
		);
	});
});
