// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import {
	auditApiAccess,
	auditReconFloor,
	buildReconAuditAppendix,
	buildReconCoverage,
} from "./recon-postcheck.js";

const CLEAN_FLOOR = auditReconFloor("nmap httpx nuclei", []);
const RECIPE = JSON.stringify({ apiBase: "http://h:8080/", authScheme: "oidc-bearer" });
const CLEAN_API = auditApiAccess(JSON.parse(RECIPE), RECIPE, "uses /api on :8080");

describe("auditReconFloor", () => {
	it("floor fully met when every floor tool leaves evidence", () => {
		expect(auditReconFloor("nmap httpx nuclei :8080", []).missingFloor).toEqual([]);
	});

	it("port-scan floor satisfied by EITHER naabu or nmap", () => {
		expect(auditReconFloor("nmap; httpx; nuclei", []).missingFloor).not.toContain(
			"port-scan",
		);
		expect(auditReconFloor("naabu; httpx; nuclei", []).missingFloor).not.toContain(
			"port-scan",
		);
	});

	it("flags a silently-skipped nuclei (the scan-00006 gap)", () => {
		expect(auditReconFloor("naabu nmap httpx katana arjun", []).missingFloor).toEqual([
			"nuclei",
		]);
	});

	it("counts scratchpad filenames as evidence", () => {
		expect(
			auditReconFloor("report", ["naabu.jsonl", "httpx.txt", "nuclei.jsonl"])
				.missingFloor,
		).toEqual([]);
	});
});

describe("auditApiAccess", () => {
	it("clean recipe → no gaps", () => {
		expect(CLEAN_API.gaps).toEqual([]);
		expect(CLEAN_API.recorded).toBe(true);
	});

	it("flags a missing recipe ONLY when the report shows an API", () => {
		expect(auditApiAccess(null, "", "static marketing site").gaps).toEqual([]);
		expect(auditApiAccess(null, "", "calls /api/v1 on :8080").gaps).toContain(
			"api-access-recipe",
		);
	});

	it("flags an incomplete recipe", () => {
		const raw = JSON.stringify({ apiBase: "http://h:8080" }); // no authScheme
		const a = auditApiAccess(JSON.parse(raw), raw, "/api");
		expect(a.gaps).toContain("api-access-auth");
		expect(a.gaps).not.toContain("api-access-base");
	});

	it("flags a leaked JWT secret in the recipe (hygiene)", () => {
		const leaked = JSON.stringify({
			apiBase: "http://h:8080",
			authScheme: "bearer",
			token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123signature",
		});
		const a = auditApiAccess(JSON.parse(leaked), leaked, "/api");
		expect(a.secretSuspected).toBe(true);
		expect(a.gaps).toContain("api-access-secret");
	});
});

describe("buildReconAuditAppendix", () => {
	it("is empty when floor and recipe are both clean", () => {
		expect(buildReconAuditAppendix(CLEAN_FLOOR, CLEAN_API)).toBe("");
	});

	it("lists missing floor tools with their reason", () => {
		const floor = auditReconFloor("nmap httpx katana", []); // nuclei missing
		const out = buildReconAuditAppendix(floor, CLEAN_API);
		expect(out).toContain("Tool-floor gaps");
		expect(out).toContain("nuclei");
	});

	it("lists API-access recipe gaps", () => {
		const api = auditApiAccess(null, "", "/api on :8080"); // missing recipe
		const out = buildReconAuditAppendix(CLEAN_FLOOR, api);
		expect(out).toContain("API-access recipe gaps");
		expect(out).toContain("api-access-recipe");
	});
});

describe("buildReconCoverage", () => {
	it("captures both floor and apiAccess verdicts", () => {
		const floor = auditReconFloor("nmap httpx", []); // nuclei missing
		const cov = buildReconCoverage(floor, CLEAN_API) as Record<string, unknown>;
		expect(cov.missingFloor).toEqual(["nuclei"]);
		expect(cov.apiAccess).toMatchObject({ recorded: true, gaps: [] });
	});
});
