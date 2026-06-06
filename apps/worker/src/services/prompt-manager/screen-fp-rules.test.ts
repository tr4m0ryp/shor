// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Screen-lane false-positive-rules include (task 016). The 7 screen templates
 * embed `@include(shared/_fp-rules.txt)`; this checks the include renders with no
 * leftover placeholder — collapsing to the (none) no-op when SHOR_FP_RULES is
 * unset, and surfacing the operator's precedents when PromptContext.fpRules is
 * populated (the seam assembleScanPromptContext feeds at scan time).
 */

import { describe, expect, it } from "vitest";
import { PROMPTS_DIR } from "../../paths.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { loadPrompt } from "./loader.js";

// The verification lane — every screen template carries the fp-rules include.
const SCREEN_PROMPTS = [
	"screen-injection",
	"screen-xss",
	"screen-auth",
	"screen-ssrf",
	"screen-authz",
	"screen-logic",
	"screen-misconfig-web",
];

// Placeholders the prompt build resolves. Checked as a closed set (not a blanket
// `{{...}}`) so a future literal SSTI payload in a body would not false-trip.
const CONTEXT_PLACEHOLDERS = [
	"{{FP_RULES}}",
	"{{THREAT_MODEL}}",
	"{{IDENTITIES}}",
	"{{WEB_URL}}",
	"{{REPO_PATH}}",
	"{{LOGIN_INSTRUCTIONS}}",
	"{{PLAYWRIGHT_SESSION}}",
];

const VARS = { webUrl: "https://target.example", repoPath: "/tmp/repo" };
const noopLogger: ActivityLogger = {
	info: () => {},
	warn: () => {},
	error: () => {},
};

function expectNoLeftoverPlaceholders(rendered: string): void {
	for (const placeholder of CONTEXT_PLACEHOLDERS) {
		expect(rendered).not.toContain(placeholder);
	}
}

describe("screen-lane fp-rules include", () => {
	for (const name of SCREEN_PROMPTS) {
		it(`${name}: renders the (none) no-op when no fp rules configured`, async () => {
			const rendered = await loadPrompt(
				name,
				VARS,
				null,
				noopLogger,
				PROMPTS_DIR,
				{},
			);
			expectNoLeftoverPlaceholders(rendered);
			// The include resolved and read as a no-op: framing present, slot -> (none).
			expect(rendered).toContain("known false positives for THIS system");
			expect(rendered).toContain("(none)");
		});

		it(`${name}: surfaces operator precedents when fpRules is populated`, async () => {
			const fpRules = "Self-XSS in the admin-only debug console is accepted risk";
			const rendered = await loadPrompt(name, VARS, null, noopLogger, PROMPTS_DIR, {
				fpRules,
			});
			expectNoLeftoverPlaceholders(rendered);
			expect(rendered).toContain(fpRules);
		});
	}
});
