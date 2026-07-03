// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import { seedKey } from "./ingest.js";
import { flagshipManifest } from "./manifest.js";

describe("flagshipManifest", () => {
	const seeds = flagshipManifest();

	it("ships at least a dozen flagship exemplars with complete provenance", () => {
		expect(seeds.length).toBeGreaterThanOrEqual(12);
		for (const s of seeds) {
			expect(s.noveltyTier).toBe("flagship");
			expect(s.tags.length).toBeGreaterThan(0);
			expect(s.provenance.url ?? "").toMatch(/^https:\/\//);
			expect(s.preconditions.length).toBeGreaterThan(0);
			expect(s.rootCause.length).toBeGreaterThan(0);
			expect(s.probeSignal.length).toBeGreaterThan(0);
		}
	});

	it("includes the Netflix 'Starting the Avalanche' algorithmic-complexity DoS", () => {
		const avalanche = seeds.find((s) => /avalanche/i.test(s.technique));
		expect(avalanche).toBeDefined();
		expect(avalanche?.cwe).toBe("CWE-400");
		expect(avalanche?.tags).toContain("cwe-407");
		expect(avalanche?.provenance.url).toBe(
			"https://netflixtechblog.com/starting-the-avalanche-640e69b14a06",
		);
	});

	it("has no duplicate dedupe keys", () => {
		const keys = seeds.map(seedKey);
		expect(new Set(keys).size).toBe(keys.length);
	});

	it("returns a defensive copy (not the shared array)", () => {
		expect(flagshipManifest()).not.toBe(flagshipManifest());
	});
});
