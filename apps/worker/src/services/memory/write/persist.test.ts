// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Write-path guarantees under test (task 011, spec T3 + T2 scrub guardrail):
 *  - scrub runs BEFORE embed — no unscrubbed text reaches the embedder/store;
 *  - both vectors + structured metadata are upserted into finding_embedding;
 *  - a refuted finding also lands in fp_memory with its decision + reason;
 *  - a scrub failure fails CLOSED — nothing is embedded or stored;
 *  - the path is a no-op when disabled or when no embed server is configured.
 */

import { describe, expect, it } from "vitest";
import { createEmbedClient, type EmbedClient } from "../embed/index.js";
import {
	createBuiltinPiiAnalyzer,
	type ScrubDeps,
	type SecretDetector,
} from "../scrub/index.js";
import {
	type FindingEmbeddingWriter,
	type FpMemoryWriter,
	type MemoryWriteContext,
	persistFinding,
	refutationDecision,
} from "./index.js";

// Fake, never-live PAT-shaped token, built from parts so no secret-shaped
// literal sits in source (would trip secret scanners); value is fake.
const FAKE_SECRET = ["ghp", "TESTONLYFAKE0123456789abcdefTESTONLY"].join("_");

const CTX: MemoryWriteContext = {
	tenantId: "t1",
	projectId: "p1",
	scanId: "s1",
};

function valueDetector(value: string): SecretDetector {
	return async (text) =>
		text.includes(value) ? [{ source: "injected", ruleId: "fake", value }] : [];
}

function scrubDeps(overrides: Partial<ScrubDeps> = {}): ScrubDeps {
	return {
		secretDetectors: [valueDetector(FAKE_SECRET)],
		piiAnalyzers: [createBuiltinPiiAnalyzer()],
		piiEngine: "injected",
		...overrides,
	};
}

interface FakeEmbed {
	client: EmbedClient;
	textInputs: string[];
	codeInputs: string[];
}

function fakeEmbed(): FakeEmbed {
	const textInputs: string[] = [];
	const codeInputs: string[] = [];
	const client: EmbedClient = {
		enabled: true,
		async embedText(texts) {
			textInputs.push(...texts);
			return {
				model: "text",
				dim: 2,
				embeddings: texts.map(() => [0.1, 0.2]),
				tokenCounts: texts.map(() => 3),
			};
		},
		async embedCode(texts) {
			codeInputs.push(...texts);
			return {
				model: "code",
				dim: 2,
				embeddings: texts.map(() => [0.3, 0.4]),
				tokenCounts: texts.map(() => 3),
			};
		},
		async rerank() {
			return [];
		},
	};
	return { client, textInputs, codeInputs };
}

function fakeEmbeddings(): {
	writer: FindingEmbeddingWriter;
	calls: Record<string, unknown>[];
} {
	const calls: Record<string, unknown>[] = [];
	return {
		calls,
		writer: {
			async create(input) {
				calls.push(input as Record<string, unknown>);
				return { id: "emb-1" };
			},
		},
	};
}

function fakeFpMemory(): {
	writer: FpMemoryWriter;
	calls: Record<string, unknown>[];
} {
	const calls: Record<string, unknown>[] = [];
	return {
		calls,
		writer: {
			async upsert(input) {
				calls.push(input as Record<string, unknown>);
				return { id: "fp-1" };
			},
		},
	};
}

const BASE_FINDING = {
	title: "Stored XSS",
	cwe: "CWE-79",
	severity: "high",
	confidence: "confirmed",
	method: "get",
	route: "/x",
	source: "req.query.q",
	sink: "res.send",
	code_snippet: `const token = "${FAKE_SECRET}"; res.send(req.query.q);`,
	evidence: `leaked ${FAKE_SECRET} in the response body`,
	vulnerable_code_location: { file: "a.js", line: 1 },
	fingerprint: "fp-abc",
};

describe("persistFinding: scrub-before-embed + dual write", () => {
	it("scrubs every text before embedding and upserts both vectors + metadata", async () => {
		const embed = fakeEmbed();
		const embeddings = fakeEmbeddings();
		const fpMemory = fakeFpMemory();
		const out = await persistFinding(BASE_FINDING, CTX, {
			embed: embed.client,
			scrubDeps: scrubDeps(),
			embeddings: embeddings.writer,
			fpMemory: fpMemory.writer,
			enabled: true,
		});

		expect(out.written).toBe(true);
		if (!out.written) return;
		expect(out.embeddingId).toBe("emb-1");
		expect(out.quarantinedSecrets).toBe(1);

		// Scrub ran first: neither embed input carries the raw secret.
		expect(embed.textInputs).toHaveLength(1);
		expect(embed.codeInputs).toHaveLength(1);
		for (const input of [...embed.textInputs, ...embed.codeInputs]) {
			expect(input).not.toContain(FAKE_SECRET);
			expect(input).toContain("[QUARANTINED-SECRET");
		}

		// Both vectors + structured columns reached the store.
		const row = embeddings.calls[0];
		expect(row).toMatchObject({
			tenantId: "t1",
			projectId: "p1",
			scanId: "s1",
			vecText: [0.1, 0.2],
			vecCode: [0.3, 0.4],
			cwe: "CWE-79",
			severity: "high",
			route: "GET /x",
			source: "req.query.q",
			sink: "res.send",
		});

		// No unscrubbed text anywhere in what reached the store.
		expect(JSON.stringify(embeddings.calls)).not.toContain(FAKE_SECRET);

		// Not a refutation -> fp_memory untouched.
		expect(fpMemory.calls).toHaveLength(0);
	});
});

describe("persistFinding: refuted findings -> fp_memory", () => {
	it("writes a refuted finding to fp_memory with a scrubbed reason", async () => {
		const embed = fakeEmbed();
		const embeddings = fakeEmbeddings();
		const fpMemory = fakeFpMemory();
		const finding = {
			...BASE_FINDING,
			fingerprint: "fp-xyz",
			disposition: "refuted_on_review",
			validation_note: `god-mode identity; also saw ${FAKE_SECRET}`,
		};
		const out = await persistFinding(finding, CTX, {
			embed: embed.client,
			scrubDeps: scrubDeps(),
			embeddings: embeddings.writer,
			fpMemory: fpMemory.writer,
			enabled: true,
		});

		expect(out.written).toBe(true);
		if (!out.written) return;
		expect(out.fpMemoryId).toBe("fp-1");
		expect(fpMemory.calls).toHaveLength(1);
		const fp = fpMemory.calls[0];
		expect(fp).toMatchObject({
			tenantId: "t1",
			projectId: "p1",
			fingerprint: "fp-xyz",
			decision: "refuted",
			vecText: [0.1, 0.2],
		});
		expect(String(fp?.reason)).toContain("god-mode");
		expect(JSON.stringify(fpMemory.calls)).not.toContain(FAKE_SECRET);
	});

	it("classifies premise_valid=false and in_scope=false", () => {
		expect(refutationDecision({ premise_valid: false })).toBe("refuted");
		expect(refutationDecision({ in_scope: false })).toBe("false_positive");
		expect(refutationDecision({ disposition: "exploited" })).toBeNull();
	});
});

describe("persistFinding: guardrails", () => {
	it("fails CLOSED on a scrub error — nothing embedded or stored", async () => {
		const embed = fakeEmbed();
		const embeddings = fakeEmbeddings();
		const fpMemory = fakeFpMemory();
		const throwingDetector: SecretDetector = async () => {
			throw new Error("engine unavailable");
		};
		const out = await persistFinding(BASE_FINDING, CTX, {
			embed: embed.client,
			scrubDeps: scrubDeps({ secretDetectors: [throwingDetector] }),
			embeddings: embeddings.writer,
			fpMemory: fpMemory.writer,
			enabled: true,
		});

		expect(out).toEqual({ written: false, reason: "scrub_failed" });
		expect(embed.textInputs).toHaveLength(0);
		expect(embed.codeInputs).toHaveLength(0);
		expect(embeddings.calls).toHaveLength(0);
		expect(fpMemory.calls).toHaveLength(0);
	});

	it("no-ops when the flag is off", async () => {
		const embed = fakeEmbed();
		const embeddings = fakeEmbeddings();
		const out = await persistFinding(BASE_FINDING, CTX, {
			embed: embed.client,
			scrubDeps: scrubDeps(),
			embeddings: embeddings.writer,
			fpMemory: fakeFpMemory().writer,
			enabled: false,
		});
		expect(out).toEqual({ written: false, reason: "disabled" });
		expect(embeddings.calls).toHaveLength(0);
	});

	it("no-ops when no embed server is configured", async () => {
		delete process.env.SHOR_EMBED_URL;
		const embeddings = fakeEmbeddings();
		const out = await persistFinding(BASE_FINDING, CTX, {
			embed: createEmbedClient(),
			scrubDeps: scrubDeps(),
			embeddings: embeddings.writer,
			fpMemory: fakeFpMemory().writer,
			enabled: true,
		});
		expect(out).toEqual({ written: false, reason: "disabled" });
		expect(embeddings.calls).toHaveLength(0);
	});
});
