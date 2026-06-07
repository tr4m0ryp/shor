// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import { buildCoverageMap } from "./coverage-map.js";

describe("buildCoverageMap", () => {
	it("returns an empty object for an empty skill map", () => {
		expect(buildCoverageMap({})).toEqual({});
	});

	it("includes every agent key present in the skill map", () => {
		const map = buildCoverageMap({
			recon: ["httpx", "nmap"],
			report: ["something-irrelevant"],
		});
		expect(Object.keys(map)).toEqual(
			expect.arrayContaining(["recon", "report"]),
		);
	});

	it("ran, missing, and floor fields are present on each entry", () => {
		const map = buildCoverageMap({ recon: ["httpx"] });
		const entry = map.recon;
		expect(entry).toBeDefined();
		expect(Array.isArray(entry?.ran)).toBe(true);
		expect(Array.isArray(entry?.missing)).toBe(true);
		expect(typeof entry?.floor).toBe("number");
	});

	it("ran only lists candidate tools (ignores off-policy tools from the tracker)", () => {
		// "report" has no policy → floor 0, ran [], missing [].
		const map = buildCoverageMap({ report: ["nmap", "sqlmap"] });
		expect(map.report?.ran).toEqual([]);
		expect(map.report?.floor).toBe(0);
	});

	it("recon entry reflects the candidate tools that were actually exercised", () => {
		// The live skillTracker is used by default; here all() returns nothing for
		// "recon" at test time, so ran will be [] (not an error).
		const map = buildCoverageMap({ recon: [] });
		expect(map.recon?.ran).toEqual([]);
		expect(typeof map.recon?.floor).toBe("number");
	});

	it("silently skips unknown agent keys without throwing", () => {
		// "totally-unknown-agent" is not a real AgentName — cast still goes through
		// evaluateCoverage which returns floor-0 ok; no crash.
		const map = buildCoverageMap({ "totally-unknown-agent": ["sqlmap"] });
		// Key is included but floor is 0 (no policy).
		expect(map["totally-unknown-agent"]?.floor).toBe(0);
	});

	it("omits shortfall when an agent meets its floor (no signal)", () => {
		// "report" has no policy → ok, so no below-floor shortfall.
		const map = buildCoverageMap({ report: ["nmap"] });
		expect(map.report?.shortfall).toBeUndefined();
	});

	it("carries the below-floor shortfall through to the artifact", () => {
		// The live skillTracker is empty at test time, so injection-vuln (floor 4 —
		// half its 8 recommended tools) has run nothing → below floor → a shortfall.
		const map = buildCoverageMap({ "injection-vuln": [] });
		const shortfall = map["injection-vuln"]?.shortfall;
		expect(shortfall).toBeDefined();
		expect(shortfall?.belowFloor).toBe(true);
		expect(shortfall?.requiredFloor).toBe(4);
		expect(shortfall?.ranTools).toBe(0);
	});
});
