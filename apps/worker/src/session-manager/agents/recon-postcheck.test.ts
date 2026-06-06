// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import {
	auditReconFloor,
	buildReconAuditAppendix,
	buildReconCoverage,
} from "./recon-postcheck.js";

describe("auditReconFloor", () => {
	it("floor fully met when every floor tool leaves evidence", () => {
		const text = "Ran nmap and httpx, then nuclei against :8080.";
		const audit = auditReconFloor(text, []);
		expect(audit.missingFloor).toEqual([]);
	});

	it("port-scan floor satisfied by EITHER naabu or nmap", () => {
		const onlyNmap = auditReconFloor("nmap -sV done; httpx ok; nuclei ran", []);
		expect(onlyNmap.missingFloor).not.toContain("port-scan");
		const onlyNaabu = auditReconFloor("naabu found ports; httpx; nuclei", []);
		expect(onlyNaabu.missingFloor).not.toContain("port-scan");
	});

	it("flags a silently-skipped nuclei (the scan-00006 gap)", () => {
		const text = "naabu + nmap + httpx + katana + arjun were run.";
		const audit = auditReconFloor(text, []);
		expect(audit.missingFloor).toEqual(["nuclei"]);
	});

	it("counts scratchpad filenames as evidence", () => {
		const audit = auditReconFloor("recon report", [
			"naabu.jsonl",
			"httpx.txt",
			"nuclei.jsonl",
		]);
		expect(audit.missingFloor).toEqual([]);
	});

	it("reports recommended tools run vs missing without warning on them", () => {
		const audit = auditReconFloor("nmap httpx nuclei katana wafw00f", []);
		expect(audit.recommendedRun).toEqual(
			expect.arrayContaining(["katana", "wafw00f"]),
		);
		expect(audit.recommendedMissing).toContain("ffuf");
		// recommended gaps never become floor gaps
		expect(audit.missingFloor).toEqual([]);
	});
});

describe("buildReconAuditAppendix", () => {
	it("is empty when the floor is fully met", () => {
		const audit = auditReconFloor("nmap httpx nuclei", []);
		expect(buildReconAuditAppendix(audit)).toBe("");
	});

	it("lists missing floor tools with their reason", () => {
		const audit = auditReconFloor("nmap httpx katana", []); // nuclei missing
		const appendix = buildReconAuditAppendix(audit);
		expect(appendix).toContain("Recon Tool-Floor Audit");
		expect(appendix).toContain("nuclei");
		expect(appendix).toContain("templated misconfig");
	});
});

describe("buildReconCoverage", () => {
	it("captures the floor verdicts in a structured shape", () => {
		const audit = auditReconFloor("nmap httpx", []); // nuclei missing
		const cov = buildReconCoverage(audit) as Record<string, unknown>;
		expect(cov.missingFloor).toEqual(["nuclei"]);
		expect(Array.isArray(cov.floor)).toBe(true);
	});
});
