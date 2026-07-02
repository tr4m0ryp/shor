// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import {
	assessLiveness,
	createLivenessState,
	type Footprint,
	type LivenessConfig,
	resolveLivenessConfig,
} from "./assess.js";

const CFG: LivenessConfig = {
	sampleIntervalMs: 1_000,
	softStallMs: 5_000,
	hardStallMs: 8_000,
	cpuEpsilonTicks: 2,
	ioEpsilonBytes: 100,
};

/** A footprint at fixed CPU/IO/message values. */
function fp(cpuTicks: number, ioBytes: number, lastMessageAt: number): Footprint {
	return { cpuTicks, ioBytes, lastMessageAt };
}

describe("assessLiveness", () => {
	it("the first sample only establishes a baseline", () => {
		const s = createLivenessState(0);
		expect(assessLiveness(s, fp(0, 0, 0), 0, CFG)).toBe("none");
		expect(s.prev).not.toBeNull();
		expect(s.lastProgressAt).toBe(0);
	});

	it("escalates soft once at softStall, then hard at hardStall when fully flat", () => {
		const s = createLivenessState(0);
		const flat = fp(0, 0, 0);
		expect(assessLiveness(s, flat, 0, CFG)).toBe("none"); // baseline
		expect(assessLiveness(s, flat, 1_000, CFG)).toBe("none");
		expect(assessLiveness(s, flat, 4_999, CFG)).toBe("none");
		expect(assessLiveness(s, flat, 5_000, CFG)).toBe("soft-kill"); // soft threshold
		expect(assessLiveness(s, flat, 6_000, CFG)).toBe("none"); // soft fires only once
		expect(assessLiveness(s, flat, 7_999, CFG)).toBe("none");
		expect(assessLiveness(s, flat, 8_000, CFG)).toBe("hard-abort"); // hard threshold
	});

	it("CPU movement above epsilon resets the stillness clock", () => {
		const s = createLivenessState(0);
		assessLiveness(s, fp(0, 0, 0), 0, CFG); // baseline
		assessLiveness(s, fp(0, 0, 0), 4_000, CFG); // still 4s
		// CPU jumps by 10 (> epsilon 2) → progress, clock resets to t=4500.
		expect(assessLiveness(s, fp(10, 0, 0), 4_500, CFG)).toBe("none");
		// 4s after the reset is still below soft (would be 9s-since-start without reset).
		expect(assessLiveness(s, fp(10, 0, 0), 8_500, CFG)).toBe("none");
		expect(assessLiveness(s, fp(10, 0, 0), 9_500, CFG)).toBe("soft-kill");
	});

	it("I/O movement above epsilon counts as progress", () => {
		const s = createLivenessState(0);
		assessLiveness(s, fp(0, 0, 0), 0, CFG);
		assessLiveness(s, fp(0, 0, 0), 5_000, CFG); // would soft-kill...
		// ...but here IO grew by 500 (> epsilon 100) on the SAME tick → no kill.
		const s2 = createLivenessState(0);
		assessLiveness(s2, fp(0, 0, 0), 0, CFG);
		expect(assessLiveness(s2, fp(0, 600, 0), 5_000, CFG)).toBe("none");
	});

	it("a newer stream message counts as progress even with flat CPU/IO", () => {
		const s = createLivenessState(0);
		assessLiveness(s, fp(0, 0, 1_000), 0, CFG);
		// CPU and IO flat, but lastMessageAt advanced → alive.
		expect(assessLiveness(s, fp(0, 0, 2_000), 5_000, CFG)).toBe("none");
	});

	it("movement at or below epsilon is treated as noise, not progress", () => {
		const s = createLivenessState(0);
		assessLiveness(s, fp(0, 0, 0), 0, CFG);
		// CPU +2 (== epsilon, not >) and IO +100 (== epsilon) → NOT progress.
		expect(assessLiveness(s, fp(2, 100, 0), 5_000, CFG)).toBe("soft-kill");
	});

	it("recovery after a soft-kill re-arms the soft step", () => {
		const s = createLivenessState(0);
		const flat = fp(0, 0, 0);
		assessLiveness(s, flat, 0, CFG); // baseline
		assessLiveness(s, flat, 5_000, CFG); // soft-kill
		// Tool nudged, work resumes: CPU jumps → progress, soft latch clears.
		expect(assessLiveness(s, fp(50, 0, 0), 5_500, CFG)).toBe("none");
		expect(s.softFired).toBe(false);
		// A fresh stall can soft-kill again.
		expect(assessLiveness(s, fp(50, 0, 0), 10_500, CFG)).toBe("soft-kill");
	});
});

describe("resolveLivenessConfig", () => {
	it("uses generous defaults that never punish slow-but-working tools", () => {
		const cfg = resolveLivenessConfig({});
		expect(cfg.softStallMs).toBe(360_000); // 6 min
		expect(cfg.hardStallMs).toBe(600_000); // 10 min
		expect(cfg.hardStallMs).toBeGreaterThan(cfg.softStallMs);
	});

	it("honors positive env overrides and ignores junk", () => {
		const cfg = resolveLivenessConfig({
			SHOR_LIVENESS_HARD_STALL_MS: "120000",
			SHOR_LIVENESS_SOFT_STALL_MS: "not-a-number",
		});
		expect(cfg.hardStallMs).toBe(120_000);
		expect(cfg.softStallMs).toBe(360_000); // junk → default
	});
});
