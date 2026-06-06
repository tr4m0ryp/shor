// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { beforeEach, describe, expect, it, vi } from "vitest";

// Mock the executor barrel so judgeFinding exercises the REAL runStructured +
// parseOr fail-open wiring without a live SDK call (same seam as run.test.ts).
const runClaudePromptMock = vi.hoisted(() => vi.fn());
vi.mock("../../ai/claude-executor/index.js", () => ({
	runClaudePrompt: runClaudePromptMock,
}));

import type { FindingRecord } from "../../job/findings/types.js";
import { judgeFinding } from "./judge.js";
import type { ManifestEntry } from "./manifest.js";

function mkFinding(id: string): FindingRecord {
	return {
		id,
		validation_note: "",
		title: `Finding ${id}`,
		category: "injection",
		cwe: "CWE-89",
		owasp_category: "A03",
		severity: "high",
		confidence: "firm",
		evidence: "",
		safe_poc: "",
		repro_steps: [],
		vulnerable_code_location: { file: "a.ts", line: 1 },
		missing_defense: "",
		remediation: "",
		status: "new",
		fingerprint: `fp-${id}`,
		partialFingerprints: {},
	};
}

const ctx = {
	deliverablesPath: "/deliverables",
	logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
};
const manifest: ManifestEntry[] = [{ cluster_id: "cl_existing", representative: mkFinding("rep") }];

describe("judgeFinding", () => {
	beforeEach(() => runClaudePromptMock.mockReset());

	it("returns the parsed judgment on a successful structured run", async () => {
		runClaudePromptMock.mockResolvedValue({
			success: true,
			duration: 1,
			structuredOutput: { judgment: "DUP_SKIP", cluster_id: "cl_existing", reason: "same sink" },
		});

		const res = await judgeFinding(mkFinding("cand"), manifest, ctx);

		expect(res).toEqual({ judgment: "DUP_SKIP", cluster_id: "cl_existing", reason: "same sink" });
	});

	it("fails open to NEW when the agent run fails", async () => {
		runClaudePromptMock.mockResolvedValue({ success: false, duration: 1, error: "boom" });

		const res = await judgeFinding(mkFinding("cand"), manifest, ctx);

		expect(res.judgment).toBe("NEW");
	});

	it("fails open to NEW when the run returns no structured output (model ignored the schema)", async () => {
		runClaudePromptMock.mockResolvedValue({ success: true, duration: 1 }); // no structuredOutput

		const res = await judgeFinding(mkFinding("cand"), manifest, ctx);

		expect(res.judgment).toBe("NEW");
	});
});
