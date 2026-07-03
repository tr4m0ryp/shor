// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import { classifyGuard, validateGuards } from "./semantic.js";
import type { GuardCandidate, GuardSemanticVerdict } from "./types.js";

function candidate(over: Partial<GuardCandidate> = {}): GuardCandidate {
	return {
		id: "abc123",
		sink: { file: "posts.ts", line: 42, code: "db.delete(id)" },
		method: "com.app.deletePost",
		vulnClass: "missing_authorization",
		cwe: "CWE-862",
		structuralVerdict: "guarded",
		dominatingGuards: [{ file: "posts.ts", line: 5, code: "isLoggedIn()" }],
		nonDominatingGuards: [],
		...over,
	};
}

const authorizes: GuardSemanticVerdict = {
	assertsAuthorization: true,
	resourceScoped: true,
	verbScoped: true,
	rationale: "checks row ownership before delete",
};
const wrongResource: GuardSemanticVerdict = {
	assertsAuthorization: true,
	resourceScoped: false, // right guard runs, WRONG resource (any-authenticated)
	verbScoped: true,
	rationale: "only checks that a user is logged in, not ownership",
};

describe("classifyGuard", () => {
	it("flags an unguarded sink structurally (no LLM needed)", () => {
		expect(classifyGuard(candidate({ structuralVerdict: "unguarded" }), { consulted: false })).toBe(
			"missing_guard",
		);
	});
	it("flags a partial guard (bypassable path) structurally", () => {
		expect(classifyGuard(candidate({ structuralVerdict: "partial_guard" }), { consulted: false })).toBe(
			"missing_guard",
		);
	});
	it("fails OPEN to adequate for a guarded sink when not consulted", () => {
		expect(classifyGuard(candidate(), { consulted: false })).toBe("adequate");
	});
	it("holds a guarded sink as unproven when consulted but undecidable", () => {
		expect(classifyGuard(candidate(), { consulted: true })).toBe("unproven");
	});
	it("catches right-guard-wrong-resource as wrong_guard", () => {
		expect(classifyGuard(candidate(), { consulted: true, semantic: wrongResource })).toBe("wrong_guard");
	});
	it("clears a guard the LLM confirms authorizes this operation", () => {
		expect(classifyGuard(candidate(), { consulted: true, semantic: authorizes })).toBe("adequate");
	});
});

describe("validateGuards", () => {
	it("catches a right-guard-wrong-resource case via semantic validation", async () => {
		const findings = await validateGuards([candidate()], {
			ask: async () => wrongResource,
		});
		expect(findings).toHaveLength(1);
		expect(findings[0]?.disposition).toBe("wrong_guard");
		expect(findings[0]?.semantic).toEqual(wrongResource);
	});

	it("emits missing_guard for structural gaps without ever calling the LLM", async () => {
		let called = 0;
		const findings = await validateGuards([candidate({ structuralVerdict: "unguarded" })], {
			ask: async () => {
				called += 1;
				return authorizes;
			},
		});
		expect(findings[0]?.disposition).toBe("missing_guard");
		expect(called).toBe(0); // LLM not consulted for structural gaps
	});

	it("holds a guarded sink as unproven when the ask throws (fail-open)", async () => {
		const findings = await validateGuards([candidate()], {
			ask: async () => {
				throw new Error("model unavailable");
			},
		});
		expect(findings[0]?.disposition).toBe("unproven");
	});

	it("fails open to adequate for a guarded sink when the semantic layer is disabled", async () => {
		const findings = await validateGuards([candidate()], { enabled: false });
		expect(findings[0]?.disposition).toBe("adequate");
	});
});
