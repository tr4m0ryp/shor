// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { afterEach, describe, expect, it, vi } from "vitest";

const runClaudePromptMock = vi.hoisted(() => vi.fn());
vi.mock("../../ai/claude-executor/index.js", () => ({
	runClaudePrompt: runClaudePromptMock,
}));

import type { FindingRecord } from "../../job/findings/types.js";
import { clusterFindings } from "./index.js";

let seq = 0;
function mkFinding(over: Partial<FindingRecord> = {}): FindingRecord {
	seq += 1;
	return {
		id: `f${seq}`,
		validation_note: "",
		title: "Finding",
		category: "ssrf",
		cwe: "CWE-918",
		owasp_category: "A10",
		severity: "high",
		confidence: "firm",
		evidence: "",
		safe_poc: "",
		repro_steps: [],
		vulnerable_code_location: { file: "a.ts", line: 1 },
		missing_defense: "",
		remediation: "",
		status: "new",
		fingerprint: `fp-${seq}`,
		partialFingerprints: {},
		...over,
	};
}

const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
const opts = { deliverablesPath: "/deliverables", logger };
const SAVED = { ...process.env };

afterEach(() => {
	process.env = { ...SAVED };
	runClaudePromptMock.mockReset();
	vi.clearAllMocks();
});

describe("clusterFindings seam", () => {
	it("is identity by default (flag off): findings unchanged, no cluster_id, no LLM", async () => {
		delete process.env.SHOR_DEDUP_JUDGE;
		const a = mkFinding();
		const b = mkFinding();

		const out = await clusterFindings([a, b], opts);

		expect(out).toEqual([a, b]); // byte-for-byte
		expect(out[0]?.cluster_id).toBeUndefined();
		expect(runClaudePromptMock).not.toHaveBeenCalled();
	});

	it("stays identity when enabled without CLI/API auth (never spawns an agent)", async () => {
		process.env.SHOR_DEDUP_JUDGE = "1";
		delete process.env.CLAUDE_CODE_OAUTH_TOKEN;
		delete process.env.ANTHROPIC_API_KEY;

		const out = await clusterFindings([mkFinding(), mkFinding()], opts);

		expect(out[0]?.cluster_id).toBeUndefined();
		expect(runClaudePromptMock).not.toHaveBeenCalled();
	});

	it("assigns cluster_ids via the judge when enabled with auth", async () => {
		process.env.SHOR_DEDUP_JUDGE = "1";
		process.env.ANTHROPIC_API_KEY = "sk-test";
		runClaudePromptMock.mockResolvedValue({
			success: true,
			duration: 1,
			structuredOutput: { judgment: "NEW", reason: "novel" },
		});

		const out = await clusterFindings([mkFinding({ fingerprint: "fa" }), mkFinding({ fingerprint: "fb" })], opts);

		expect(out).toHaveLength(2);
		expect(out[0]?.cluster_id).toBeTruthy();
		expect(out[1]?.cluster_id).toBeTruthy();
		// First finding clusters with an empty manifest (no LLM); the second is judged.
		expect(runClaudePromptMock).toHaveBeenCalledTimes(1);
	});
});
