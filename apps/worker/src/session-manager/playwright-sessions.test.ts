// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import { AGENTS } from "../session-manager.js";
import { PLAYWRIGHT_SESSION_MAPPING } from "./playwright-sessions.js";

const CATEGORIES = [
	"injection",
	"xss",
	"auth",
	"ssrf",
	"authz",
	"logic",
	"misconfig-web",
];
const VULN = CATEGORIES.map((c) => `vuln-${c}`);
const EXPLOIT = CATEGORIES.map((c) => `exploit-${c}`);

describe("PLAYWRIGHT_SESSION_MAPPING — full-width browser isolation", () => {
	it("every vuln category maps to a DISTINCT session (no shared profile at 7-wide)", () => {
		const sessions = VULN.map((a) => PLAYWRIGHT_SESSION_MAPPING[a]);
		expect(sessions.every(Boolean)).toBe(true); // all mapped (no agent1 fallback)
		expect(new Set(sessions).size).toBe(VULN.length); // all distinct
	});

	it("every exploit category maps to a DISTINCT session", () => {
		const sessions = EXPLOIT.map((a) => PLAYWRIGHT_SESSION_MAPPING[a]);
		expect(sessions.every(Boolean)).toBe(true);
		expect(new Set(sessions).size).toBe(EXPLOIT.length);
	});

	it("each category reuses the SAME session across vuln→exploit (auth/state reuse)", () => {
		for (const c of CATEGORIES) {
			expect(PLAYWRIGHT_SESSION_MAPPING[`vuln-${c}`]).toBe(
				PLAYWRIGHT_SESSION_MAPPING[`exploit-${c}`],
			);
		}
	});

	it("EVERY registered agent is declared — no silent loadPrompt fallback", () => {
		// loadPrompt now throws for an undeclared agent instead of falling back to a
		// shared session. This pins the map exhaustive: a new agent without a session
		// declaration fails HERE (CI), never silently at runtime.
		const templates = [
			...new Set(Object.values(AGENTS).map((a) => a.promptTemplate)),
		];
		const undeclared = templates.filter(
			(t) => !(t in PLAYWRIGHT_SESSION_MAPPING),
		);
		expect(undeclared).toEqual([]);
	});
});
