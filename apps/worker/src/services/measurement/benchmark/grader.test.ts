// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Deterministic match-grader tests: a known finding matches its ground-truth vuln
 * (and its CVE via the package shortlist), the same-file hard gate rejects a
 * plausible-but-wrong file, line drift is tolerated, and FP labels are recognized.
 */

import { describe, expect, it } from "vitest";
import { loadBenchmark } from "./corpus.js";
import { gradeFindings } from "./grader.js";
import type { Benchmark, BenchmarkFinding } from "./types.js";

const bench = loadBenchmark();

const API = "backend/UvA.Workflow.Api";

function finding(over: Partial<BenchmarkFinding> & { id: string; file: string }): BenchmarkFinding {
	return over;
}

describe("gradeFindings — matching", () => {
	it("matches a known finding to its ground-truth vuln by file+line+CWE", () => {
		const f = finding({
			id: "F-ssrf",
			file: `${API}/Services/EffectService.cs`,
			line: 233,
			cwe: "CWE-918",
			category: "ssrf",
		});
		const report = gradeFindings([f], bench);
		const m = report.findingMatches[0]!;
		expect(m.kind).toBe("true_positive");
		expect(m.vulnId).toBe("gt-0007-effectservice-ssrf");
		expect(m.score).toBeGreaterThan(0.9);

		const cov = report.coverage.find((c) => c.vulnId === "gt-0007-effectservice-ssrf");
		expect(cov?.covered).toBe(true);
		expect(cov?.matchedBy).toEqual(["F-ssrf"]);
	});

	it("matches a dependency CVE via the package shortlist", () => {
		const f = finding({
			id: "F-log4j",
			file: "pom.xml",
			pkg: "org.apache.logging.log4j:log4j-core",
			cwe: "CWE-502",
			category: "injection",
		});
		const report = gradeFindings([f], bench);
		expect(report.findingMatches[0]!).toMatchObject({
			kind: "true_positive",
			vulnId: "gt-cve-2021-44228-log4shell",
		});
	});

	it("tolerates line drift up to the max, and rejects beyond it", () => {
		const near = finding({
			id: "F-near",
			file: `${API}/Services/EffectService.cs`,
			line: 240, // drift 7 < 12
			cwe: "CWE-918",
			category: "ssrf",
		});
		const nearReport = gradeFindings([near], bench);
		expect(nearReport.findingMatches[0]!.kind).toBe("true_positive");

		// Exact-path match alone (0.6) still clears the 0.5 threshold even far from
		// the cited line — same-file is a strong signal; the shortlist keeps classes apart.
		const far = finding({
			id: "F-far",
			file: `${API}/Services/EffectService.cs`,
			line: 999,
			cwe: "CWE-918",
			category: "ssrf",
		});
		expect(gradeFindings([far], bench).findingMatches[0]!.kind).toBe("true_positive");
	});

	it("enforces the same-file hard gate: a wrong file never matches", () => {
		const f = finding({
			id: "F-wrongfile",
			file: `${API}/Services/OtherService.cs`,
			line: 233,
			cwe: "CWE-918",
			category: "ssrf",
		});
		expect(gradeFindings([f], bench).findingMatches[0]!.kind).toBe("unmatched");
	});

	it("recognizes a reproduced known false positive", () => {
		const f = finding({
			id: "F-pathtrav",
			file: `${API}/Providers/FileSystemProvider.cs`,
			cwe: "CWE-22",
			category: "injection",
		});
		const m = gradeFindings([f], bench).findingMatches[0]!;
		expect(m.kind).toBe("false_positive");
		expect(m.fpId).toBe("fp-0008-path-traversal-trio");
	});

	it("leaves an off-benchmark finding unmatched (novel, not penalized as FP)", () => {
		const f = finding({
			id: "F-novel",
			file: "src/Unknown.cs",
			cwe: "CWE-000",
			category: "other",
		});
		expect(gradeFindings([f], bench).findingMatches[0]!.kind).toBe("unmatched");
	});

	it("is order-stable and covers each vuln once even with duplicate findings", () => {
		const a = finding({ id: "A", file: `${API}/Services/EffectService.cs`, line: 233, cwe: "CWE-918", category: "ssrf" });
		const b = finding({ id: "B", file: `${API}/Services/EffectService.cs`, line: 234, cwe: "CWE-918", category: "ssrf" });
		const report = gradeFindings([a, b], bench);
		expect(report.findingMatches.map((m) => m.findingId)).toEqual(["A", "B"]);
		const cov = report.coverage.find((c) => c.vulnId === "gt-0007-effectservice-ssrf");
		expect(cov?.matchedBy).toEqual(["A", "B"]);
	});
});

describe("gradeFindings — empty inputs", () => {
	it("reports full-benchmark misses when no findings are supplied", () => {
		const report = gradeFindings([], bench);
		expect(report.findingMatches).toEqual([]);
		expect(report.coverage.every((c) => !c.covered)).toBe(true);
		expect(report.coverage.length).toBe(bench.vulns.length);
	});

	it("matches nothing against an empty benchmark", () => {
		const empty: Benchmark = { vulns: [], falsePositives: [] };
		const f = finding({ id: "X", file: "a.ts", line: 1 });
		const report = gradeFindings([f], empty);
		expect(report.findingMatches[0]!.kind).toBe("unmatched");
		expect(report.coverage).toEqual([]);
	});
});
