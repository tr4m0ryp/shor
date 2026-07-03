// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * CLI flag-gating under test (no file side effects — only the DRY-RUN and the
 * flag-on-but-no-embed branches are exercised; both write nothing to disk):
 *  - `SHOR_SEED_GLOBAL` unset -> dry run, returns 0, prints the plan;
 *  - `SHOR_SEED_GLOBAL=1` with no embed server -> clean no-op, returns 0;
 *  - `collectUnits` always yields the flagship set, tolerating a bad CAPEC path.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import { collectUnits, runSeedCli } from "./cli.js";

const NOOP: ActivityLogger = {
	info: () => {},
	warn: () => {},
	error: () => {},
};

afterEach(() => {
	vi.restoreAllMocks();
});

describe("runSeedCli", () => {
	it("dry-runs (writes nothing) when SHOR_SEED_GLOBAL is unset", async () => {
		const log = vi.spyOn(console, "log").mockImplementation(() => {});
		const code = await runSeedCli({});
		expect(code).toBe(0);
		const printed = log.mock.calls.map((c) => String(c[0])).join("\n");
		expect(printed).toContain("SEED DRY RUN");
		expect(printed).toContain("Avalanche");
	});

	it("no-ops cleanly when the flag is on but no embed server is configured", async () => {
		delete process.env.SHOR_EMBED_URL;
		vi.spyOn(console, "log").mockImplementation(() => {});
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const code = await runSeedCli({ SHOR_SEED_GLOBAL: "1" });
		expect(code).toBe(0);
		const warned = warn.mock.calls.map((c) => String(c[0])).join("\n");
		expect(warned).toContain("SHOR_EMBED_URL is unset");
	});
});

describe("collectUnits", () => {
	it("returns the flagship set and tolerates an unreadable CAPEC path", () => {
		const units = collectUnits(
			{ SHOR_CAPEC_STIX_PATH: "/no/such/bundle.json" },
			NOOP,
		);
		expect(units.length).toBeGreaterThanOrEqual(12);
		expect(units.every((u) => u.noveltyTier === "flagship")).toBe(true);
	});
});
