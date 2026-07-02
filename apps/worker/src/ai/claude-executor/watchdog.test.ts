// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import {
	createWatchdogState,
	recordAssistantTurn,
	shouldTrigger,
} from "./watchdog.js";

const SAVE = ["bash -lc 'save-deliverable pre_recon_deliverable.md'"];
const NOSAVE = ["bash -lc 'ls -la'"];

describe("watchdog: post-save budget resets on every save", () => {
	it("does NOT trip while the agent keeps saving chunks past the budget", () => {
		// Regression: a large deliverable written in chunks (one save per chunk)
		// must not look like a stale loop. Previously the budget anchored on the
		// FIRST save, so this tripped ~40 turns after the first chunk.
		const s = createWatchdogState();
		recordAssistantTurn(s, 5, "writing the deliverable in chunks", SAVE);
		for (let t = 15; t <= 200; t += 10) {
			recordAssistantTurn(s, t, "next chunk", SAVE);
			expect(shouldTrigger(s, t)).toBeNull();
		}
	});

	it("DOES trip when many turns pass with no save after the last save", () => {
		const s = createWatchdogState();
		recordAssistantTurn(s, 5, "saved once", SAVE);
		// 40 turns later, still no further save -> genuine stale loop.
		recordAssistantTurn(s, 45, "still spinning", NOSAVE);
		expect(shouldTrigger(s, 45)).toMatch(/since save-deliverable/);
	});

	it("never arms the post-save budget before any save", () => {
		const s = createWatchdogState();
		recordAssistantTurn(s, 100, "exploring", NOSAVE);
		expect(shouldTrigger(s, 100)).toBeNull();
	});
});
