// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import { RECOMMENDED, recommendedSkillsSection } from "./skill-recommendations.js";

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
