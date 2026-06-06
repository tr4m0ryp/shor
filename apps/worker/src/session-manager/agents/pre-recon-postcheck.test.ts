// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import type { CoverageAudit } from "../../job/coverage/census.js";
import {
	auditSections,
	buildAuditAppendix,
	buildPreReconIndex,
} from "./pre-recon-postcheck.js";

/** A deliverable carrying every contracted heading (abbreviated bodies). */
const FULL = [
	"# Pre-recon",
	"## 1. Executive Summary",
	"## 3. Authentication & Authorization Deep Dive",
	"## 5. Attack Surface Analysis",
	"## 7. Injection Sources (Command Injection and SQL Injection)",
	"## 8. Critical File Paths",
	"## 9. XSS Sinks and Render Contexts",
	"## 10. SSRF Sinks",
].join("\n\n");

const fullCoverage: CoverageAudit = {
	total: 4,
	covered: 4,
	uncovered: [],
	ratio: 1,
};

describe("auditSections", () => {
	it("reports no gaps when every required section is present", () => {
		const audit = auditSections(FULL);
		expect(audit.missing).toEqual([]);
		expect(audit.drifted).toEqual([]);
	});

	it("flags a missing required section", () => {
		const audit = auditSections(FULL.replace("## 10. SSRF Sinks", ""));
		expect(audit.missing).toContain(10);
	});

	it("flags a drifted heading (right number, wrong title)", () => {
		const audit = auditSections(
			FULL.replace(
				"## 9. XSS Sinks and Render Contexts",
				"## 9. Output Encoding",
			),
		);
		expect(audit.drifted).toContain(9);
		expect(audit.missing).not.toContain(9);
	});

	it("records a char offset for present sections", () => {
		const audit = auditSections(FULL);
		const s8 = audit.sections.find((s) => s.num === 8);
		expect(s8?.present).toBe(true);
		expect(typeof s8?.charOffset).toBe("number");
	});
});

describe("buildAuditAppendix", () => {
	it("is empty when coverage is full and the contract is met", () => {
		expect(buildAuditAppendix(fullCoverage, auditSections(FULL))).toBe("");
	});

	it("lists uncovered files and summarizes the overflow", () => {
		const uncovered = Array.from({ length: 45 }, (_, i) => `Svc/File${i}.cs`);
		const coverage: CoverageAudit = {
			total: 50,
			covered: 5,
			uncovered,
			ratio: 0.1,
		};
		const appendix = buildAuditAppendix(coverage, auditSections(FULL));
		expect(appendix).toContain("Uncovered backend source files");
		expect(appendix).toContain("5/50");
		expect(appendix).toContain("Svc/File0.cs");
		// 45 uncovered, sample of 40 → 5 summarized as "and more".
		expect(appendix).toContain("and **5** more");
	});

	it("surfaces section-contract warnings", () => {
		const audit = auditSections(
			FULL.replace(
				"## 7. Injection Sources (Command Injection and SQL Injection)",
				"",
			),
		);
		const appendix = buildAuditAppendix(fullCoverage, audit);
		expect(appendix).toContain("Missing required sections");
		expect(appendix).toContain("7");
	});
});

describe("buildPreReconIndex", () => {
	it("captures sections + coverage in a structured shape", () => {
		const index = buildPreReconIndex(
			"pre_recon_deliverable.md",
			auditSections(FULL),
			fullCoverage,
		) as Record<string, unknown>;
		expect(index.deliverable).toBe("pre_recon_deliverable.md");
		expect(index.missingSections).toEqual([]);
		expect(index.coverage).toMatchObject({
			backendSourceFiles: 4,
			cited: 4,
			uncovered: 0,
			ratio: 1,
		});
	});
});
