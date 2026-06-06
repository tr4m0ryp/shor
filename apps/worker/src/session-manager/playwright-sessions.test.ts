// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
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
});
