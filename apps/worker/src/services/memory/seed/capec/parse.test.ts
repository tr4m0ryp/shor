// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import { SAMPLE_CAPEC_BUNDLE } from "./fixture.js";
import { parseCapecStix } from "./parse.js";

describe("parseCapecStix", () => {
	const seeds = parseCapecStix(SAMPLE_CAPEC_BUNDLE);

	it("selects attack-patterns and skips identity + revoked objects", () => {
		expect(seeds.map((s) => s.technique)).toEqual([
			"SQL Injection",
			"Relative Path Traversal",
		]);
	});

	it("maps CAPEC fields onto the exemplar shape (known tier)", () => {
		const sqli = seeds[0];
		expect(sqli).toBeDefined();
		if (!sqli) return;
		expect(sqli.noveltyTier).toBe("known");
		expect(sqli.capecId).toBe("CAPEC-66");
		expect(sqli.cwe).toBe("CWE-89");
		expect(sqli.aliases).toEqual(["SQLi"]);
		expect(sqli.preconditions).toContain("builds SQL from untrusted input");
		expect(sqli.preconditions).toContain("No parameterization");
		expect(sqli.rootCause).toContain("alter the intended query");
		expect(sqli.pocSkeleton).toContain("' OR '1'='1");
		expect(sqli.sink).toContain("Read Data");
		expect(sqli.tags).toEqual(
			expect.arrayContaining(["capec", "software", "standard"]),
		);
		expect(sqli.provenance).toMatchObject({
			source: "MITRE CAPEC",
			url: "https://capec.mitre.org/data/definitions/66.html",
		});
	});

	it("yields an empty PoC skeleton when no example instance exists", () => {
		const traversal = seeds[1];
		expect(traversal?.pocSkeleton).toBe("");
		expect(traversal?.capecId).toBe("CAPEC-139");
	});

	it("accepts a bare objects array and rejects garbage input", () => {
		expect(
			parseCapecStix([{ type: "attack-pattern", name: "X" }]),
		).toHaveLength(1);
		expect(parseCapecStix(null)).toEqual([]);
		expect(parseCapecStix({ nope: true })).toEqual([]);
		expect(parseCapecStix("string")).toEqual([]);
	});
});
