// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * fpv1 fingerprint + structural gate (spec T6). Under test:
 *  - fpv1 is stable under line-number drift and comment/whitespace churn;
 *  - fpv1 differs across file / CWE (co-located distinct weaknesses);
 *  - the structural gate agrees only on a shared anchor (file/CWE/endpoint/
 *    component), matching the 017 same/different pairs.
 */

import { describe, expect, it } from "vitest";
import {
	codeRegionHash,
	computeFpv1,
	structuralAgree,
	structuralKeyOf,
} from "./fingerprint.js";

const BASE = {
	cwe: "CWE-639",
	category: "authz",
	sink: "db.Users.Find",
	vulnerable_code_location: { file: "backend/Controllers/UsersController.cs", line: 10 },
	code_snippet: "var u = db.Users.Find(id); return Ok(u);",
};

describe("computeFpv1: drift tolerance", () => {
	it("is identical under line-number shift + added comments/whitespace", () => {
		const a = computeFpv1(BASE);
		const b = computeFpv1({
			...BASE,
			vulnerable_code_location: { file: BASE.vulnerable_code_location.file, line: 187 },
			code_snippet: "// re-audited later\n\n  var u = db.Users.Find(id);   return Ok(u);",
		});
		expect(a).toBe(b);
		expect(a.startsWith("fpv1:")).toBe(true);
	});

	it("differs when the file differs", () => {
		const other = computeFpv1({
			...BASE,
			vulnerable_code_location: { file: "backend/Controllers/InvitesController.cs", line: 10 },
		});
		expect(other).not.toBe(computeFpv1(BASE));
	});

	it("differs when the CWE differs at the same location", () => {
		const other = computeFpv1({ ...BASE, cwe: "CWE-306" });
		expect(other).not.toBe(computeFpv1(BASE));
	});

	it("is total: a near-empty finding still yields a value", () => {
		expect(computeFpv1({}).startsWith("fpv1:")).toBe(true);
	});
});

describe("codeRegionHash", () => {
	it("ignores comments + whitespace, keys on the code tokens", () => {
		const h1 = codeRegionHash("foo(bar);  // note");
		const h2 = codeRegionHash("  foo(bar);\n/* block */");
		expect(h1).toBe(h2);
		expect(codeRegionHash("foo(baz);")).not.toBe(h1);
	});

	it("returns null for empty/absent code", () => {
		expect(codeRegionHash("")).toBeNull();
		expect(codeRegionHash(null)).toBeNull();
	});
});

describe("structuralAgree: the gate", () => {
	const key = (f: Record<string, unknown>) => structuralKeyOf(f);

	it("agrees on same file even when CWE labels differ (017 Users pair)", () => {
		const a = key({ cwe: "CWE-639", category: "authz", vulnerable_code_location: { file: "x/UsersController.cs", line: 1 } });
		const b = key({ cwe: "CWE-862", category: "authz", vulnerable_code_location: { file: "x/UsersController.cs", line: 9 } });
		expect(structuralAgree(a, b)).toBe(true);
	});

	it("blocks SSRF-in-one-file vs XSS-in-another (017 distinct pair)", () => {
		const ssrf = key({ cwe: "CWE-918", category: "ssrf", vulnerable_code_location: { file: "svc/EffectService.cs", line: 1 } });
		const xss = key({ cwe: "CWE-79", category: "xss", vulnerable_code_location: { file: "web/MarkdownRenderer.tsx", line: 1 } });
		expect(structuralAgree(ssrf, xss)).toBe(false);
	});

	it("blocks two different controllers' authz gaps (distinct roots)", () => {
		const invites = key({ cwe: "CWE-862", category: "authz", vulnerable_code_location: { file: "x/InvitesController.cs", line: 1 } });
		const users = key({ cwe: "CWE-639", category: "authz", vulnerable_code_location: { file: "x/UsersController.cs", line: 1 } });
		expect(structuralAgree(invites, users)).toBe(false);
	});

	it("agrees on a shared endpoint anchor across files", () => {
		const a = key({ route: "POST /api/versions", cwe: "CWE-306", vulnerable_code_location: { file: "a.cs", line: 1 } });
		const b = key({ route: "POST /api/versions", cwe: "CWE-862", vulnerable_code_location: { file: "b.cs", line: 1 } });
		expect(structuralAgree(a, b)).toBe(true);
	});

	it("never treats absent-on-both axes as agreement", () => {
		const a = key({ category: "authz" });
		const b = key({ category: "authz" });
		expect(structuralAgree(a, b)).toBe(false);
	});
});
