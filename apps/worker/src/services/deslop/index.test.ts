// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it, vi } from "vitest";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { FindingRecord } from "../../job/findings/types.js";
import { deslopFindings, rewriteRemediation } from "./index.js";

function mockLogger(): ActivityLogger & { info: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn> } {
	return { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
}

const BOILERPLATE =
	"Apply the missing defense: validate the token audience. See the attack-surface deliverable for the context-correct fix prompt.";

function finding(over: Partial<FindingRecord>): FindingRecord {
	return {
		id: "f1",
		category: "auth",
		remediation: BOILERPLATE,
		missing_defense: "validate the token audience",
		evidence: "",
		safe_poc: "",
		repro_steps: [],
		vulnerable_code_location: { file: "src/auth/token.ts", line: 42 },
		...over,
	} as FindingRecord;
}

describe("rewriteRemediation — no fabrication", () => {
	it("rewrites boilerplate to a finding-specific line anchored on its own file:line + missing_defense", () => {
		const out = rewriteRemediation(finding({}));
		expect(out).toBeTruthy();
		expect(out).toContain("src/auth/token.ts:42");
		expect(out).toContain("validate the token audience");
		// The slop pointer is gone.
		expect(out).not.toMatch(/attack-surface deliverable/i);
	});

	it("references a route + sink ONLY when present in the finding's own evidence", () => {
		const out = rewriteRemediation(
			finding({
				category: "injection",
				missing_defense: "",
				remediation:
					"Apply the context-correct injection defense; see the attack-surface deliverable for the fix prompt.",
				evidence: "The GET /api/items endpoint passes id into db.query(sql) unsanitized.",
				vulnerable_code_location: { file: "src/items.ts", line: 10 },
			}),
		);
		expect(out).toContain("src/items.ts:10");
		expect(out).toContain("/api/items");
		expect(out).toContain("db.query");
		// Uses the class-standard injection fix (no fabricated target fact).
		expect(out).toMatch(/parameterized/i);
	});

	it("does NOT invent an anchor: no location, no evidence, no defense -> declines (null)", () => {
		const out = rewriteRemediation(
			finding({
				missing_defense: "",
				remediation:
					"Apply the context-correct auth defense; see the attack-surface deliverable for the fix prompt.",
				evidence: "",
				safe_poc: "",
				repro_steps: [],
				vulnerable_code_location: { file: "", line: 0 },
			}),
		);
		expect(out).toBeNull();
	});

	it("returns null for a remediation that is already finding-specific (nothing to do)", () => {
		expect(
			rewriteRemediation(
				finding({ remediation: "Remove [AllowAnonymous] on VersionsController.cs:8 and gate the route." }),
			),
		).toBeNull();
	});
});

describe("deslopFindings — orchestration", () => {
	it("is an identity no-op when disabled (stock run unchanged, no logs)", () => {
		const logger = mockLogger();
		const recs = [finding({})];
		const { records, stats } = deslopFindings(recs, logger, false);
		expect(records).toBe(recs);
		expect(stats).toEqual({ boilerplate: 0, rewritten: 0, unspecifiable: 0 });
		expect(logger.info).not.toHaveBeenCalled();
	});

	it("rewrites boilerplate, flags remediation_deslopped, clears remediation_boilerplate", () => {
		const logger = mockLogger();
		const rec = finding({ remediation_boilerplate: true } as Partial<FindingRecord>);
		const { records, stats } = deslopFindings([rec], logger, true);
		expect(stats.rewritten).toBe(1);
		const out = records[0];
		expect(out?.remediation).not.toBe(BOILERPLATE);
		expect(out?.remediation_deslopped).toBe(true);
		expect(out?.remediation_boilerplate).toBeUndefined();
		// Original input not mutated.
		expect(rec.remediation).toBe(BOILERPLATE);
	});

	it("flags an unspecifiable boilerplate finding instead of inventing a fix", () => {
		const logger = mockLogger();
		const rec = finding({
			missing_defense: "",
			remediation:
				"Apply the context-correct auth defense; see the attack-surface deliverable for the fix prompt.",
			evidence: "",
			vulnerable_code_location: { file: "", line: 0 },
		});
		const { records, stats } = deslopFindings([rec], logger, true);
		expect(stats.unspecifiable).toBe(1);
		expect(stats.rewritten).toBe(0);
		expect(records[0]?.remediation_deslop_unspecifiable).toBe(true);
		expect(records[0]?.remediation).toBe(rec.remediation);
		expect(logger.warn).toHaveBeenCalled();
	});

	it("leaves a non-boilerplate finding untouched", () => {
		const logger = mockLogger();
		const rec = finding({ remediation: "Bind the artifact token to the requesting user and rotate the key." });
		const { records, stats } = deslopFindings([rec], logger, true);
		expect(stats.boilerplate).toBe(0);
		expect(records[0]).toBe(rec);
	});
});
