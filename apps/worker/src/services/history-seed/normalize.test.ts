// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import {
	extractCveIds,
	normalizeHistoricalSignal,
	redactSecrets,
} from "./normalize.js";
import { renderHistoricalSeed } from "./render.js";
import { HISTORY_CAPS } from "./types.js";

describe("normalizeHistoricalSignal", () => {
	it("returns the empty signal for garbage / missing input", () => {
		expect(normalizeHistoricalSignal(undefined)).toEqual({
			hotFiles: [],
			depCves: [],
		});
		expect(normalizeHistoricalSignal("nonsense")).toEqual({
			hotFiles: [],
			depCves: [],
		});
		expect(normalizeHistoricalSignal({ other: 1 })).toEqual({
			hotFiles: [],
			depCves: [],
		});
	});

	it("coerces a well-formed signal and preserves required fields", () => {
		const out = normalizeHistoricalSignal({
			hotFiles: [
				{
					file: "src/auth/login.ts",
					commits: [
						{ sha: "abc123", date: "2024-01-02", subject: "fix auth bypass" },
					],
				},
			],
			depCves: [
				{
					package: "lodash",
					version: "4.17.20",
					id: "CVE-2021-23337",
					severity: "HIGH",
					fixedVersion: "4.17.21",
				},
			],
		});
		expect(out.hotFiles[0]?.file).toBe("src/auth/login.ts");
		expect(out.hotFiles[0]?.commits[0]?.sha).toBe("abc123");
		expect(out.depCves[0]).toEqual({
			package: "lodash",
			version: "4.17.20",
			id: "CVE-2021-23337",
			severity: "HIGH",
			fixedVersion: "4.17.21",
		});
	});

	it("drops commits with no sha and hot files with no path", () => {
		const out = normalizeHistoricalSignal({
			hotFiles: [
				{ file: "", commits: [{ sha: "x", date: "", subject: "" }] },
				{
					file: "a.ts",
					commits: [{ date: "2024-01-01", subject: "noisy" }, { sha: "ok" }],
				},
			],
		});
		expect(out.hotFiles).toHaveLength(1);
		expect(out.hotFiles[0]?.file).toBe("a.ts");
		expect(out.hotFiles[0]?.commits).toHaveLength(1);
		expect(out.hotFiles[0]?.commits[0]?.sha).toBe("ok");
	});

	it("dedups commits by sha and caps commits per file", () => {
		const commits = Array.from({ length: 20 }, (_, i) => ({
			sha: `sha${i % 3}`, // only 3 distinct shas
			date: "2024-01-01",
			subject: "security fix",
		}));
		const out = normalizeHistoricalSignal({
			hotFiles: [{ file: "a.ts", commits }],
		});
		expect(out.hotFiles[0]?.commits).toHaveLength(3);
	});

	it("drops dep CVEs missing package or id and dedups them", () => {
		const out = normalizeHistoricalSignal({
			depCves: [
				{ package: "", id: "CVE-1", version: "1" },
				{ package: "p", version: "1" }, // no id
				{ package: "p", version: "1", id: "CVE-2", severity: "LOW" },
				{ package: "p", version: "1", id: "CVE-2", severity: "LOW" }, // dup
			],
		});
		expect(out.depCves).toHaveLength(1);
		expect(out.depCves[0]?.id).toBe("CVE-2");
		expect(out.depCves[0]?.fixedVersion).toBeUndefined();
		expect(out.depCves[0]?.severity).toBe("LOW");
	});

	it("defaults missing version/severity to 'unknown'", () => {
		const out = normalizeHistoricalSignal({
			depCves: [{ package: "p", id: "CVE-9" }],
		});
		expect(out.depCves[0]?.version).toBe("unknown");
		expect(out.depCves[0]?.severity).toBe("unknown");
	});

	it("backfills hot-file cves from commit subjects", () => {
		const out = normalizeHistoricalSignal({
			hotFiles: [
				{
					file: "x.ts",
					commits: [
						{ sha: "a", date: "2024-01-01", subject: "patch CVE-2021-44228" },
					],
				},
			],
		});
		expect(out.hotFiles[0]?.cves).toEqual(["CVE-2021-44228"]);
	});

	it("ranks hot files by commit count and caps the list", () => {
		const hotFiles = Array.from(
			{ length: HISTORY_CAPS.hotFiles + 5 },
			(_, i) => ({
				file: `f${i}.ts`,
				commits: [{ sha: `s${i}`, date: "2024-01-01", subject: "fix" }],
			}),
		);
		// Give one file many commits — it must survive the cap and rank first.
		hotFiles[hotFiles.length - 1] = {
			file: "busiest.ts",
			commits: Array.from({ length: 5 }, (_, j) => ({
				sha: `b${j}`,
				date: "2024-01-01",
				subject: "fix",
			})),
		};
		const out = normalizeHistoricalSignal({ hotFiles });
		expect(out.hotFiles.length).toBe(HISTORY_CAPS.hotFiles);
		expect(out.hotFiles[0]?.file).toBe("busiest.ts");
	});

	it("redacts secret-looking tokens in commit subjects", () => {
		const out = normalizeHistoricalSignal({
			hotFiles: [
				{
					file: "leak.ts",
					commits: [
						{
							sha: "a",
							date: "2024-01-01",
							subject: "remove " + "AKIA" + "IOSFODNN7EXAMPLE" + " and password = hunter2longvalue",
						},
					],
				},
			],
		});
		const subject = out.hotFiles[0]?.commits[0]?.subject ?? "";
		expect(subject).not.toContain("" + "AKIA" + "IOSFODNN7EXAMPLE" + "");
		expect(subject).not.toContain("hunter2longvalue");
		expect(subject).toContain("[REDACTED]");
	});

	it("truncates over-long subjects to the cap", () => {
		const out = normalizeHistoricalSignal({
			hotFiles: [
				{
					file: "a.ts",
					commits: [{ sha: "a", date: "2024-01-01", subject: "x".repeat(500) }],
				},
			],
		});
		expect(out.hotFiles[0]?.commits[0]?.subject.length).toBe(
			HISTORY_CAPS.subjectLen,
		);
	});
});

describe("redactSecrets / extractCveIds helpers", () => {
	it("masks GitHub and Slack tokens", () => {
		const masked = redactSecrets(
			"token " + "ghp_0123456789abcdefghij" + "ABCDEFGHIJ012345" + " xoxb-12345678-abcdefghij",
		);
		expect(masked).not.toContain("ghp_0123456789");
		expect(masked).not.toContain("xoxb-12345678");
	});

	it("extracts and dedups CVE ids case-insensitively", () => {
		expect(
			extractCveIds("fixes cve-2021-44228 and CVE-2021-44228 plus CVE-2022-1234"),
		).toEqual(["CVE-2021-44228", "CVE-2022-1234"]);
	});
});

describe("renderHistoricalSeed", () => {
	it("returns empty string for an empty signal", () => {
		expect(renderHistoricalSeed({ hotFiles: [], depCves: [] })).toBe("");
	});

	it("renders hot files and dep CVEs into a compact brief", () => {
		const seed = renderHistoricalSeed({
			hotFiles: [
				{
					file: "src/auth.ts",
					commits: [{ sha: "a", date: "2024-01-01", subject: "fix auth bypass" }],
					cves: ["CVE-2021-1"],
				},
			],
			depCves: [
				{
					package: "lodash",
					version: "4.17.20",
					id: "CVE-2021-23337",
					severity: "HIGH",
					fixedVersion: "4.17.21",
				},
			],
		});
		expect(seed).toContain("src/auth.ts");
		expect(seed).toContain("CVE-2021-1");
		expect(seed).toContain("fix auth bypass");
		expect(seed).toContain("lodash@4.17.20");
		expect(seed).toContain("fixed in 4.17.21");
	});
});
