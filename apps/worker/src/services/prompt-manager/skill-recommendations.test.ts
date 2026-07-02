// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import { PROMPTS_DIR } from "../../paths.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { interpolateVariables } from "./interpolation.js";
import { loadPrompt } from "./loader.js";
import { applyPromptContext } from "./prompt-context.js";
import { RECOMMENDED, recommendedSkillsSection } from "./skill-recommendations.js";

/** Swallow logger so the render path runs quietly. */
const silentLogger: ActivityLogger = {
	info: () => {},
	warn: () => {},
	error: () => {},
};

describe("recommendedSkillsSection", () => {
	it("renders a recon agent as a checklist with breadth + justify rules", () => {
		const reconTools = RECOMMENDED.recon ?? [];
		expect(reconTools.length).toBeGreaterThan(0);
		const out = recommendedSkillsSection("recon");
		// One checklist line per recommended tool, mirrored into TodoWrite.
		expect(out).toContain("TodoWrite");
		for (const tool of reconTools) {
			expect(out).toContain(`- [ ] \`${tool}\` — ran | skipped:`);
		}
		expect(out).toContain("Breadth before depth");
		expect(out).toContain("Justify every skip");
		// Must point at scope/rate-limit rather than mandate spraying.
		expect(out).toContain("rate-limit");
		expect(out.toLowerCase()).toContain("not a mandate to spray");
	});

	it("renders an exploit agent the same way (checklist + breadth + justify)", () => {
		const exploitTools = RECOMMENDED["exploit-injection"] ?? [];
		expect(exploitTools.length).toBeGreaterThan(0);
		const out = recommendedSkillsSection("exploit-injection");
		for (const tool of exploitTools) {
			expect(out).toContain(`- [ ] \`${tool}\` — ran | skipped:`);
		}
		expect(out).toContain("Breadth before depth");
		expect(out).toContain("Justify every skip");
		expect(out).toContain("FAILED phase");
	});

	it("returns \"\" for a synthesis agent (report)", () => {
		expect(recommendedSkillsSection("report")).toBe("");
	});

	it("returns \"\" for an unknown agent name", () => {
		expect(recommendedSkillsSection("attack-surface")).toBe("");
		expect(recommendedSkillsSection("totally-unknown")).toBe("");
	});
});

describe("prompt-context interpolation", () => {
	it("renders an existing prompt with no leftover {{...}} placeholders", async () => {
		const rendered = await loadPrompt(
			"recon",
			{ webUrl: "https://example.test", repoPath: "/tmp/repo" },
			null,
			silentLogger,
		);
		// Sanity: real variables landed, and nothing is left unresolved.
		expect(rendered).toContain("https://example.test");
		expect(rendered).not.toMatch(/\{\{[^}]+\}\}/);
	});

	it("lands a provided context value and resolves the rest to sentinels", async () => {
		const out = await interpolateVariables(
			"TM={{THREAT_MODEL}} | PART={{PARTITION}} | V={{VOTER_INDEX}} | ID={{IDENTITIES}}",
			{ webUrl: "https://example.test", repoPath: "/tmp/repo" },
			null,
			silentLogger,
			PROMPTS_DIR,
			{ threatModel: "TM-SUMMARY", voterIndex: 2 },
		);
		expect(out).toContain("TM=TM-SUMMARY");
		expect(out).toContain("V=2");
		// Unsupplied vars fall back to the neutral sentinel, never a literal.
		expect(out).toContain("PART=(none)");
		expect(out).toContain("ID=(none)");
		expect(out).not.toMatch(/\{\{[^}]+\}\}/);
	});

	it("substitutes neutral sentinels for absent context and honours index 0", () => {
		expect(applyPromptContext("[{{FP_RULES}}]")).toBe("[(none)]");
		expect(applyPromptContext("[{{LENS}}]", { lens: "discovery" })).toBe(
			"[discovery]",
		);
		// A zero ordinal is a real value, not "absent".
		expect(applyPromptContext("[{{VOTER_INDEX}}]", { voterIndex: 0 })).toBe(
			"[0]",
		);
	});
});
