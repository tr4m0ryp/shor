// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { afterEach, describe, expect, it } from "vitest";
import { resolveJoernBins, runTaintAnalysis, taintEnabled } from "./driver.js";

const saved = { ...process.env };
afterEach(() => {
	process.env = { ...saved };
});

describe("taintEnabled — flag gate (default OFF)", () => {
	it("is OFF unless SHOR_TAINT=1", () => {
		delete process.env.SHOR_TAINT;
		expect(taintEnabled()).toBe(false);
		process.env.SHOR_TAINT = "true";
		expect(taintEnabled()).toBe(false);
		process.env.SHOR_TAINT = "1";
		expect(taintEnabled()).toBe(true);
	});
});

describe("resolveJoernBins", () => {
	it("returns null when neither PATH nor SHOR_JOERN_DIR provides joern", async () => {
		const bins = await resolveJoernBins({ PATH: "/nonexistent/bin" });
		expect(bins).toBeNull();
	});
});

describe("runTaintAnalysis — fail-open, never throws", () => {
	it("returns degraded:disabled when the flag is off (stock scan unchanged)", async () => {
		delete process.env.SHOR_TAINT;
		const res = await runTaintAnalysis("/tmp/does-not-matter");
		expect(res.observations).toHaveLength(0);
		expect(res.degraded?.reason).toBe("disabled");
	});

	it("returns degraded:joern_missing when enabled but Joern is absent", async () => {
		process.env.SHOR_TAINT = "1";
		process.env.PATH = "/nonexistent/bin";
		delete process.env.SHOR_JOERN_DIR;
		const res = await runTaintAnalysis("/tmp/does-not-matter");
		expect(res.observations).toHaveLength(0);
		expect(res.degraded?.reason).toBe("joern_missing");
	});
});
