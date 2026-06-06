// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
