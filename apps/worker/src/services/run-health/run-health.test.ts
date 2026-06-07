// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import { buildAlerts } from "./summary.js";
import {
	classifyVote,
	summarizeCategoryScreen,
	type VoteClass,
} from "./screen.js";
import { summarizeCategoryTools } from "./tools.js";

/** Build a verdicts array: each entry's votes from a list of reasons. */
function verdicts(...entries: string[][]): unknown {
	return entries.map((reasons, i) => ({
		id: `V-${i}`,
		votes: reasons.map((reason, v) => ({ voter: v + 1, reason })),
	}));
}

describe("classifyVote", () => {
	const cases: [string, VoteClass][] = [
		["voter produced no structured verdict (fail-open)", "failopen"],
		["unreachable: http://h:8080 returned connection refused", "unreachable"],
		["Confirmed: ACAO:* on /auth via live curl probe", "real"],
		["Cannot refute: backend not deployed", "real"],
	];
	for (const [reason, want] of cases) {
		it(`classifies "${reason.slice(0, 32)}…" as ${want}`, () => {
			expect(classifyVote(reason)).toBe(want);
		});
	}
});

describe("summarizeCategoryScreen", () => {
	it("counts real / fail-open / unreachable and the fail-open rate", () => {
		const v = verdicts(
			["real reason", "voter produced no structured verdict (fail-open)", "fail-open"],
			["unreachable: nothing on :8080", "real two", "real three"],
		);
		const s = summarizeCategoryScreen("xss", v);
		expect(s.entries).toBe(2);
		expect(s.totalVotes).toBe(6);
		expect(s.failOpen).toBe(2);
		expect(s.unreachable).toBe(1);
		expect(s.real).toBe(3);
		expect(s.failOpenRate).toBeCloseTo(2 / 6);
	});

	it("is empty (rate 0) for a missing/empty verdicts file", () => {
		const s = summarizeCategoryScreen("injection", undefined);
		expect(s.totalVotes).toBe(0);
		expect(s.failOpenRate).toBe(0);
	});
});

describe("summarizeCategoryTools", () => {
	it("derives toolEvidence from floorMet or recommendedRun", () => {
		expect(
			summarizeCategoryTools("misconfig-web", {
				floorMet: true,
				recommendedRun: ["nuclei"],
			}).toolEvidence,
		).toBe(true);
		expect(
			summarizeCategoryTools("xss", { floorMet: false, recommendedRun: [] })
				.toolEvidence,
		).toBe(false);
		expect(summarizeCategoryTools("logic", undefined).toolEvidence).toBe(false);
	});
});

describe("buildAlerts", () => {
	it("flags heavy fail-open, unreachable hits, and zero tool evidence", () => {
		const screen = [
			summarizeCategoryScreen(
				"xss",
				verdicts([
					"voter produced no structured verdict (fail-open)",
					"fail-open",
					"unreachable: :8080 refused",
				]),
			),
			summarizeCategoryScreen("misconfig-web", verdicts(["real", "real", "real"])),
		];
		const tools = [
			summarizeCategoryTools("xss", { floorMet: false, recommendedRun: [] }),
			summarizeCategoryTools("misconfig-web", { floorMet: true, recommendedRun: [] }),
		];
		const alerts = buildAlerts(screen, tools);
		expect(alerts.some((a) => a.includes("screen xss") && a.includes("fail-opened"))).toBe(true);
		expect(alerts.some((a) => a.includes("screen xss") && a.includes("unreachable"))).toBe(true);
		expect(alerts.some((a) => a.includes("vuln xss") && a.includes("no evidence"))).toBe(true);
		// The healthy category raises nothing.
		expect(alerts.some((a) => a.includes("misconfig-web"))).toBe(false);
	});

	it("stays silent when every category is healthy", () => {
		const screen = [summarizeCategoryScreen("auth", verdicts(["real", "real"]))];
		const tools = [summarizeCategoryTools("auth", { floorMet: true, recommendedRun: [] })];
		expect(buildAlerts(screen, tools)).toEqual([]);
	});
});
