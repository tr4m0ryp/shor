// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import type { ClaudePromptResult } from "../../../../ai/claude-executor/index.js";
import type { StructuredResult } from "../../../../ai/structured/index.js";
import type { SeedProvenance } from "../types.js";
import { distillWriteup, type StructuredRunner } from "./distill.js";

const RAW =
	"A long public write-up describing a novel SSRF-via-redirect trick.";
const PROVENANCE: SeedProvenance = {
	source: "Research Blog",
	url: "https://example.com/writeup",
	date: "2025",
};

const RAW_STUB = { success: true, duration: 0 } as ClaudePromptResult;

/** A runner that captures the prompt and returns a fixed distilled object. */
function okRunner(distilled: Record<string, unknown>): {
	runStructured: StructuredRunner;
	prompts: string[];
} {
	const prompts: string[] = [];
	const runStructured: StructuredRunner = async <T>(args: {
		prompt: string;
	}): Promise<StructuredResult<T>> => {
		prompts.push(args.prompt);
		return { ok: true, value: distilled as T, raw: RAW_STUB };
	};
	return { runStructured, prompts };
}

const DISTILLED = {
	technique: "SSRF via redirect",
	preconditions: "fetcher follows redirects",
	rootCause: "allowlist checked once",
	source: "attacker URL",
	sink: "internal service",
	probeSignal: "internal content returned",
	pocSkeleton: "GET /fetch?url=...",
	cwe: "CWE-918",
	tags: ["SSRF", "Redirect"],
};

describe("distillWriteup", () => {
	it("distills a write-up into a novel-tier exemplar with provenance", async () => {
		const { runStructured, prompts } = okRunner(DISTILLED);
		const out = await distillWriteup(RAW, {
			runStructured,
			provenance: PROVENANCE,
		});
		expect(out).not.toBeNull();
		if (!out) return;
		expect(out.noveltyTier).toBe("novel");
		expect(out.technique).toBe("SSRF via redirect");
		expect(out.cwe).toBe("CWE-918");
		expect(out.tags).toEqual(["ssrf", "redirect"]); // lowercased
		expect(out.provenance).toEqual(PROVENANCE);
		// The raw source text is passed to the model but NEVER stored on the result.
		expect(JSON.stringify(out)).not.toContain(RAW);
		expect(prompts[0]).toContain(RAW);
	});

	it("returns null on empty input without invoking the runner", async () => {
		const { runStructured, prompts } = okRunner(DISTILLED);
		expect(
			await distillWriteup("   ", { runStructured, provenance: PROVENANCE }),
		).toBeNull();
		expect(prompts).toHaveLength(0);
	});

	it("returns null when the structured call fails", async () => {
		const runStructured: StructuredRunner = async () => ({
			ok: false,
			error: "no structured output",
			raw: RAW_STUB,
		});
		expect(
			await distillWriteup(RAW, { runStructured, provenance: PROVENANCE }),
		).toBeNull();
	});

	it("returns null when required fields are missing", async () => {
		const { runStructured } = okRunner({ technique: "Only a name" });
		expect(
			await distillWriteup(RAW, { runStructured, provenance: PROVENANCE }),
		).toBeNull();
	});
});
