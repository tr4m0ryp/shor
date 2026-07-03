// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it, vi } from "vitest";
import type { ActivityLogger } from "../../types/activity-logger.js";
import {
	deriveCategorySignals,
	gateCategory,
	gateTarget,
	triageConfigFromEnv,
} from "./gate.js";
import { runTriage } from "./index.js";
import type { TriageConfig } from "./types.js";

const ACTIVE: TriageConfig = { enabled: true, observeOnly: false, minCategorySurface: 1 };
const OBSERVE: TriageConfig = { enabled: true, observeOnly: true, minCategorySurface: 1 };

function mockLogger(): ActivityLogger & { info: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn> } {
	return { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
}

describe("triage gate — pure deciders", () => {
	it("skips a target only when a probe determined it unreachable", () => {
		const v = gateTarget(
			{ target: "https://dead.example", reachable: false, reachabilityDetermined: true },
			ACTIVE,
		);
		expect(v.decision).toBe("skip");
		expect(v.reason).toMatch(/did not respond/i);
	});

	it("biases to scan when reachability was never determined (never drops a real target)", () => {
		const v = gateTarget(
			{ target: "https://maybe.example", reachable: false, reachabilityDetermined: false },
			ACTIVE,
		);
		expect(v.decision).toBe("scan");
		expect(v.reason).toMatch(/not determined/i);
	});

	it("scans a reachable target", () => {
		const v = gateTarget(
			{ target: "https://live.example", reachable: true, reachabilityDetermined: true },
			ACTIVE,
		);
		expect(v.decision).toBe("scan");
	});

	it("skips a category recon probed with zero surface hits, with a specific reason", () => {
		const v = gateCategory({ category: "ssrf", probed: true, surfaceHits: 0 }, ACTIVE);
		expect(v.decision).toBe("skip");
		expect(v.reason).toContain("ssrf");
		expect(v.reason).toMatch(/hits=0/);
	});

	it("scans a probed category with surface, and an un-probed category (bias to scan)", () => {
		expect(gateCategory({ category: "xss", probed: true, surfaceHits: 3 }, ACTIVE).decision).toBe("scan");
		expect(gateCategory({ category: "xss", probed: false, surfaceHits: 0 }, ACTIVE).decision).toBe("scan");
	});

	it("observe-only downgrades a would-be skip to scan but records wouldSkip", () => {
		const v = gateCategory({ category: "auth", probed: true, surfaceHits: 0 }, OBSERVE);
		expect(v.decision).toBe("scan");
		expect(v.wouldSkip).toBe(true);
		expect(v.reason).toMatch(/^observe-only:/);
	});
});

describe("deriveCategorySignals", () => {
	it("counts distinct surface markers from a recon blob", () => {
		const sigs = deriveCategorySignals("POST /login with password; JWT session token", ["auth", "ssrf"]);
		const auth = sigs.find((s) => s.category === "auth");
		const ssrf = sigs.find((s) => s.category === "ssrf");
		expect(auth && auth.surfaceHits).toBeGreaterThan(0);
		expect(ssrf && ssrf.surfaceHits).toBe(0);
		expect(auth?.probed).toBe(true);
	});

	it("honors an explicit probed=false so the gate keeps biasing to scan", () => {
		const [sig] = deriveCategorySignals("nothing relevant here", ["logic"], false);
		expect(sig?.probed).toBe(false);
	});
});

describe("runTriage — orchestration + logging", () => {
	it("is an identity no-op when disabled: no verdicts, no logs, all categories cleared", () => {
		const logger = mockLogger();
		const r = runTriage(
			{ categories: [{ category: "xss", probed: true, surfaceHits: 0 }] },
			logger,
			{ enabled: false, observeOnly: false, minCategorySurface: 1 },
		);
		expect(r.verdicts).toHaveLength(0);
		expect(r.skipped).toHaveLength(0);
		expect(r.scanCategories).toEqual(["xss"]);
		expect(logger.warn).not.toHaveBeenCalled();
		expect(logger.info).not.toHaveBeenCalled();
	});

	it("logs every skip (never silent) and removes only skipped categories from scanCategories", () => {
		const logger = mockLogger();
		const r = runTriage(
			{
				target: { target: "https://live.example", reachable: true, reachabilityDetermined: true },
				categories: [
					{ category: "xss", probed: true, surfaceHits: 2 },
					{ category: "ssrf", probed: true, surfaceHits: 0 },
				],
			},
			logger,
			ACTIVE,
		);
		expect(r.scanCategories).toEqual(["xss"]);
		expect(r.skipped.map((s) => s.subject)).toEqual(["ssrf"]);
		const warned = logger.warn.mock.calls.some(
			([msg, attrs]) => /skipping/i.test(String(msg)) && (attrs as { subject?: string })?.subject === "ssrf",
		);
		expect(warned).toBe(true);
	});

	it("surfaces a target skip as an extra explicit warning", () => {
		const logger = mockLogger();
		runTriage(
			{ target: { target: "https://dead.example", reachable: false, reachabilityDetermined: true } },
			logger,
			ACTIVE,
		);
		const flagged = logger.warn.mock.calls.some(([msg]) => /TARGET flagged unreachable/.test(String(msg)));
		expect(flagged).toBe(true);
	});
});

describe("triageConfigFromEnv", () => {
	const KEY = "SHOR_TRIAGE_GATE";
	const MIN = "SHOR_TRIAGE_MIN_SURFACE";
	it("defaults to disabled when unset", () => {
		const prev = process.env[KEY];
		delete process.env[KEY];
		expect(triageConfigFromEnv().enabled).toBe(false);
		if (prev !== undefined) process.env[KEY] = prev;
	});

	it("parses 1 -> enabled, observe -> observe-only, and a min-surface override", () => {
		const prevKey = process.env[KEY];
		const prevMin = process.env[MIN];
		process.env[KEY] = "1";
		expect(triageConfigFromEnv()).toMatchObject({ enabled: true, observeOnly: false });
		process.env[KEY] = "observe";
		expect(triageConfigFromEnv()).toMatchObject({ enabled: true, observeOnly: true });
		process.env[MIN] = "3";
		expect(triageConfigFromEnv().minCategorySurface).toBe(3);
		if (prevKey === undefined) delete process.env[KEY]; else process.env[KEY] = prevKey;
		if (prevMin === undefined) delete process.env[MIN]; else process.env[MIN] = prevMin;
	});
});
