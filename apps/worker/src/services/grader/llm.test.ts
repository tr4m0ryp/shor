// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Async LLM grader tests (T13). The executor barrel is mocked so no real SDK call
 * happens; the real `runStructured`/`parseOr` run against the mock. Proves the
 * fail-open guarantee: a failed/rejected grader collapses to the finding's
 * existing labels, and a successful pass persists grades for the sync consumer.
 */

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

const runClaudePromptMock = vi.hoisted(() => vi.fn());
vi.mock("../../ai/claude-executor/index.js", () => ({
	runClaudePrompt: runClaudePromptMock,
}));

import type { FindingRecord } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { GRADES_FILE, defaultGradeFor, gradeWriteup, runGraderPass } from "./index.js";

const logger = { info() {}, warn() {}, error() {} } as unknown as ActivityLogger;

function mkFinding(o: Partial<FindingRecord> = {}): FindingRecord {
	return {
		id: "F1",
		validation_note: "",
		title: "Stored XSS",
		category: "xss",
		cwe: "CWE-79",
		owasp_category: "A03",
		severity: "medium",
		confidence: "firm",
		evidence: "Payload rendered unescaped in the comment body.",
		safe_poc: "<script>1</script>",
		repro_steps: ["POST /comments"],
		vulnerable_code_location: { file: "src/comments.ts", line: 30 },
		missing_defense: "",
		remediation: "",
		status: "new",
		fingerprint: "fp",
		partialFingerprints: {},
		...o,
	};
}

describe("gradeWriteup / runGraderPass", () => {
	beforeEach(() => runClaudePromptMock.mockReset());

	it("returns the LLM grade and persists rows on success", async () => {
		runClaudePromptMock.mockResolvedValue({
			success: true,
			duration: 1,
			structuredOutput: {
				evidence_score: 2,
				severity: "high",
				reachability: "REACHABLE",
				confidence: "firm",
			},
		});
		const dir = await fs.mkdtemp(path.join(os.tmpdir(), "shor-grader-llm-"));
		try {
			const rows = await runGraderPass([mkFinding()], { deliverablesPath: dir, logger });

			expect(rows).toHaveLength(1);
			expect(rows[0]).toMatchObject({ id: "F1", evidence_score: 2, reachability: "REACHABLE" });

			const written = JSON.parse(await fs.readFile(path.join(dir, GRADES_FILE), "utf8"));
			expect(written.grades[0]).toMatchObject({ id: "F1", evidence_score: 2 });
		} finally {
			await fs.rm(dir, { recursive: true, force: true });
		}
	});

	it("fails open to the finding's existing labels when the grader run fails", async () => {
		runClaudePromptMock.mockResolvedValue({ success: false, duration: 1, error: "boom" });
		const finding = mkFinding({ severity: "medium", confidence: "firm", reachability: "UNCLEAR" });

		const grade = await gradeWriteup(finding, { deliverablesPath: "/tmp", logger });

		expect(grade).toEqual(defaultGradeFor(finding));
		expect(grade.severity).toBe("medium");
		expect(grade.confidence).toBe("firm");
		expect(grade.evidence_score).toBe(1); // firm -> moderate fallback
	});

	it("fails open when the model returns no structured object", async () => {
		// Grader ran but ignored the schema (no structuredOutput): runStructured
		// reports ok:false, so parseOr keeps the finding's existing labels.
		runClaudePromptMock.mockResolvedValue({ success: true, duration: 1 });
		const finding = mkFinding({ confidence: "confirmed" });

		const grade = await gradeWriteup(finding, { deliverablesPath: "/tmp", logger });

		expect(grade).toEqual(defaultGradeFor(finding));
		expect(grade.evidence_score).toBe(2); // confirmed -> strong fallback
	});
});
