// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Seed-ingest guarantees under test:
 *  - each unique exemplar -> one `exemplar` row with `sourceTenant: null`
 *    (public seed) and a `seeded: true` payload marker;
 *  - Vector A always embedded; Vector B only when a PoC skeleton exists;
 *  - dedupe by capecId, else technique + data-flow source;
 *  - clean no-op skips (embed disabled / empty input) — never a throw.
 */

import { describe, expect, it } from "vitest";
import { createEmbedClient, type EmbedClient } from "../embed/index.js";
import { seedGlobalPool } from "./ingest.js";
import type { GlobalPoolWriter, SeedExemplar } from "./types.js";

function mkSeed(overrides: Partial<SeedExemplar> = {}): SeedExemplar {
	return {
		technique: "Technique A",
		preconditions: "pre",
		rootCause: "root",
		source: "attacker input",
		sink: "dangerous op",
		probeSignal: "signal",
		pocSkeleton: "POC()",
		tags: ["t"],
		noveltyTier: "flagship",
		provenance: { source: "Src", url: "https://example.com" },
		...overrides,
	};
}

type PoolCall = Parameters<GlobalPoolWriter["insert"]>[0];

function fakeEmbed(): EmbedClient {
	return {
		enabled: true,
		async embedText(texts) {
			return {
				model: "t",
				dim: 2,
				embeddings: texts.map(() => [0.1, 0.2]),
				tokenCounts: [],
			};
		},
		async embedCode(texts) {
			return {
				model: "c",
				dim: 2,
				embeddings: texts.map(() => [0.3, 0.4]),
				tokenCounts: [],
			};
		},
		async rerank() {
			return [];
		},
	};
}

function fakeWriter(): { writer: GlobalPoolWriter; calls: PoolCall[] } {
	const calls: PoolCall[] = [];
	return {
		calls,
		writer: {
			async insert(input) {
				calls.push(input);
				return { id: `row-${calls.length}` };
			},
		},
	};
}

describe("seedGlobalPool", () => {
	it("writes one public exemplar row per unique seed with both vectors", async () => {
		const { writer, calls } = fakeWriter();
		const units = [mkSeed(), mkSeed({ technique: "Technique B" })];
		const res = await seedGlobalPool(units, { embed: fakeEmbed(), writer });

		expect(res.seeded).toBe(2);
		expect(res.poolIds).toEqual(["row-1", "row-2"]);
		expect(calls).toHaveLength(2);
		const first = calls[0];
		expect(first).toMatchObject({
			kind: "exemplar",
			sourceTenant: null,
			vecText: [0.1, 0.2],
			vecCode: [0.3, 0.4],
		});
		expect(first?.payload).toMatchObject({
			seeded: true,
			technique: "Technique A",
			noveltyTier: "flagship",
			provenance: { source: "Src", url: "https://example.com" },
		});
	});

	it("omits the code vector for an exemplar with no PoC skeleton", async () => {
		const { writer, calls } = fakeWriter();
		const units = [
			mkSeed({ technique: "With PoC" }),
			mkSeed({ technique: "No PoC", pocSkeleton: "" }),
		];
		await seedGlobalPool(units, { embed: fakeEmbed(), writer });
		expect(calls[0]?.vecCode).toEqual([0.3, 0.4]);
		expect(calls[1]?.vecCode).toBeNull();
		expect(calls[1]?.vecText).toEqual([0.1, 0.2]);
	});

	it("dedupes by capecId, then by technique + source", async () => {
		const { writer, calls } = fakeWriter();
		const units = [
			mkSeed({ technique: "One", capecId: "CAPEC-1" }),
			mkSeed({ technique: "Renamed", capecId: "CAPEC-1" }), // dup capecId
			mkSeed({ technique: "Two", source: "input-x" }),
			mkSeed({ technique: "Two", source: "input-x" }), // dup technique+source
			mkSeed({ technique: "Two", source: "input-y" }), // distinct source -> kept
		];
		const res = await seedGlobalPool(units, { embed: fakeEmbed(), writer });
		expect(res.seeded).toBe(3);
		expect(res.skipped).toBe(2);
		expect(calls).toHaveLength(3);
	});

	it("skips cleanly when the embed client is disabled", async () => {
		delete process.env.SHOR_EMBED_URL;
		const { writer, calls } = fakeWriter();
		const res = await seedGlobalPool([mkSeed()], {
			embed: createEmbedClient(),
			writer,
		});
		expect(res).toMatchObject({ seeded: 0, reason: "embed_disabled" });
		expect(calls).toHaveLength(0);
	});

	it("skips cleanly on empty input", async () => {
		const { writer, calls } = fakeWriter();
		const res = await seedGlobalPool([], { embed: fakeEmbed(), writer });
		expect(res).toMatchObject({ seeded: 0, reason: "empty" });
		expect(calls).toHaveLength(0);
	});
});
