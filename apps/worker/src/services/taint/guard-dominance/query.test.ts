// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import {
	buildGuardDominanceScript,
	GUARD_CWE,
	parseGuardResults,
	structuralVerdict,
} from "./query.js";
import type { GuardRawResult } from "./types.js";

describe("buildGuardDominanceScript", () => {
	const script = buildGuardDominanceScript();

	it("is a Joern @main script that imports the CPG and writes the out-file", () => {
		expect(script).toContain("@main def exec(cpgFile: String, outFile: String)");
		expect(script).toContain("importCpg(cpgFile)");
		expect(script).toContain("os.write.over(os.Path(outFile)");
	});

	it("uses a real CFG dominator query, not a text scan", () => {
		expect(script).toContain("sink.dominatedBy.id.toSet");
		expect(script).toContain("dominating");
		expect(script).toContain("nonDominating");
	});

	it("matches guards and sinks by NAME or CODE (the JS/TS frontend fix)", () => {
		expect(script).toContain("cpg.call.name(pats: _*) ++ cpg.call.code(pats: _*)");
	});

	it("compares node identity by .id (traversals return fresh wrappers)", () => {
		expect(script).toContain("g.method.id == mId");
		expect(script).toContain("domIds.contains(g.id)");
	});

	it("honors caller matcher overrides", () => {
		const s = buildGuardDominanceScript({ guards: ["myGuard"], sinks: ["myDelete"] });
		expect(s).toContain("myGuard");
		expect(s).toContain("myDelete");
	});
});

describe("structuralVerdict", () => {
	const g = { file: "a.ts", line: 1, code: "requireAuth()" };
	it("is guarded when a dominating guard exists", () => {
		expect(structuralVerdict([g], [])).toBe("guarded");
	});
	it("is partial_guard when a guard exists but does not dominate", () => {
		expect(structuralVerdict([], [g])).toBe("partial_guard");
	});
	it("is unguarded when no guard is present at all", () => {
		expect(structuralVerdict([], [])).toBe("unguarded");
	});
});

describe("parseGuardResults", () => {
	it("flags a sink NOT dominated by any guard (the core detection)", () => {
		const raw: GuardRawResult = {
			results: [
				{
					sink: { file: "posts.ts", line: 42, code: "db.delete(id)", method: "deletePost" },
					method: "com.app.deletePost",
					dominatingGuards: [],
					nonDominatingGuards: [{ file: "posts.ts", line: 30, code: "isLoggedIn()" }],
				},
			],
		};
		const [cand] = parseGuardResults(raw);
		expect(cand?.structuralVerdict).toBe("partial_guard");
		expect(cand?.cwe).toBe(GUARD_CWE);
		expect(cand?.dominatingGuards).toHaveLength(0);
		expect(cand?.id).toMatch(/^[0-9a-f]{16}$/);
	});

	it("marks a dominated sink as guarded (a candidate for semantic review)", () => {
		const raw: GuardRawResult = {
			results: [
				{
					sink: { file: "acct.ts", line: 10, code: "setRole()" },
					method: "com.app.setRole",
					dominatingGuards: [{ file: "acct.ts", line: 5, code: "requireAdmin()" }],
					nonDominatingGuards: [],
				},
			],
		};
		const [cand] = parseGuardResults(raw);
		expect(cand?.structuralVerdict).toBe("guarded");
		expect(cand?.dominatingGuards).toHaveLength(1);
	});

	it("is total over garbage input (fail-open parse)", () => {
		expect(parseGuardResults({} as GuardRawResult)).toEqual([]);
		expect(parseGuardResults({ results: [{}] } as unknown as GuardRawResult)).toEqual([]);
	});

	it("gives distinct ids to distinct sinks and a stable id to the same sink", () => {
		const mk = (line: number): GuardRawResult => ({
			results: [{ sink: { file: "x.ts", line, code: "del()" }, method: "m" }],
		});
		const a = parseGuardResults(mk(1))[0];
		const b = parseGuardResults(mk(2))[0];
		const a2 = parseGuardResults(mk(1))[0];
		expect(a?.id).not.toBe(b?.id);
		expect(a?.id).toBe(a2?.id);
	});
});
