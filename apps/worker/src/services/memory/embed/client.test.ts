// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createEmbedClient, EmbedError, MAX_RERANK } from "./index.js";

const SAVED = { ...process.env };
const fetchMock = vi.fn();

function jsonResponse(body: unknown, ok = true, status = 200): Response {
	return {
		ok,
		status,
		json: async () => body,
	} as unknown as Response;
}

beforeEach(() => {
	fetchMock.mockReset();
	vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
	process.env = { ...SAVED };
	vi.unstubAllGlobals();
});

describe("createEmbedClient (no-op when SHOR_EMBED_URL unset)", () => {
	it("is disabled and makes no network call", async () => {
		delete process.env.SHOR_EMBED_URL;
		const client = createEmbedClient();

		expect(client.enabled).toBe(false);
		expect(await client.embedCode(["x"])).toEqual({
			model: "",
			dim: 0,
			embeddings: [],
			tokenCounts: [],
		});
		expect(await client.embedText(["x"])).toEqual({
			model: "",
			dim: 0,
			embeddings: [],
			tokenCounts: [],
		});
		expect(await client.rerank("q", ["a", "b"])).toEqual([]);
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

describe("embedCode request shape + response parsing", () => {
	beforeEach(() => {
		process.env.SHOR_EMBED_URL = "https://embed.local/";
		process.env.SHOR_EMBED_TOKEN = "secret-token";
	});

	it("POSTs /embed/code with normalize + truncate_dim and bearer auth", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse({
				model: "codesage/codesage-large-v2",
				dim: 1024,
				embeddings: [[0.1, 0.2]],
				token_counts: [7],
			}),
		);

		const client = createEmbedClient();
		const res = await client.embedCode(["snippet"]);

		expect(fetchMock).toHaveBeenCalledTimes(1);
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("https://embed.local/embed/code"); // trailing slash trimmed
		expect(init.method).toBe("POST");
		const headers = init.headers as Record<string, string>;
		expect(headers.authorization).toBe("Bearer secret-token");
		expect(JSON.parse(init.body as string)).toEqual({
			inputs: ["snippet"],
			normalize: true,
			truncate_dim: 1024,
		});
		expect(res.model).toBe("codesage/codesage-large-v2");
		expect(res.dim).toBe(1024);
		expect(res.embeddings).toEqual([[0.1, 0.2]]);
		expect(res.tokenCounts).toEqual([7]); // length hint surfaced
	});

	it("respects a custom truncateDim and normalize=false", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse({ model: "m", dim: 512, embeddings: [[1]], token_counts: [3] }),
		);
		const client = createEmbedClient();
		await client.embedCode(["s"], { truncateDim: 512, normalize: false });

		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(JSON.parse(init.body as string)).toEqual({
			inputs: ["s"],
			normalize: false,
			truncate_dim: 512,
		});
	});
});

describe("embedText", () => {
	beforeEach(() => {
		process.env.SHOR_EMBED_URL = "https://embed.local";
		delete process.env.SHOR_EMBED_TOKEN;
	});

	it("POSTs /embed/text without truncate_dim and no auth header when tokenless", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse({
				model: "Alibaba-NLP/gte-large-en-v1.5",
				dim: 1024,
				embeddings: [[0.3]],
				token_counts: [5],
			}),
		);
		const client = createEmbedClient();
		await client.embedText(["hello world"]);

		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("https://embed.local/embed/text");
		const body = JSON.parse(init.body as string);
		expect(body).toEqual({ inputs: ["hello world"], normalize: true });
		expect(body.truncate_dim).toBeUndefined();
		const headers = init.headers as Record<string, string>;
		expect(headers.authorization).toBeUndefined();
	});
});

describe("batching", () => {
	beforeEach(() => {
		process.env.SHOR_EMBED_URL = "https://embed.local";
	});

	it("chunks inputs beyond batchSize into multiple calls and concatenates", async () => {
		fetchMock
			.mockResolvedValueOnce(
				jsonResponse({ model: "m", dim: 2, embeddings: [[1], [2]], token_counts: [1, 1] }),
			)
			.mockResolvedValueOnce(
				jsonResponse({ model: "m", dim: 2, embeddings: [[3]], token_counts: [1] }),
			);

		const client = createEmbedClient({ baseUrl: "https://embed.local", batchSize: 2 });
		const res = await client.embedText(["a", "b", "c"]);

		expect(fetchMock).toHaveBeenCalledTimes(2);
		expect(res.embeddings).toEqual([[1], [2], [3]]);
		expect(res.tokenCounts).toEqual([1, 1, 1]);
	});
});

describe("rerank", () => {
	beforeEach(() => {
		process.env.SHOR_EMBED_URL = "https://embed.local";
	});

	it("POSTs query + passages and returns hits; caps input at MAX_RERANK", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResponse({
				model: "BAAI/bge-reranker-v2-m3",
				results: [
					{ index: 1, score: 0.9 },
					{ index: 0, score: 0.2 },
				],
			}),
		);
		const passages = Array.from({ length: MAX_RERANK + 10 }, (_, i) => `p${i}`);
		const client = createEmbedClient();
		const hits = await client.rerank("query", passages, { topK: 5 });

		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("https://embed.local/rerank");
		const body = JSON.parse(init.body as string);
		expect(body.query).toBe("query");
		expect(body.passages).toHaveLength(MAX_RERANK); // capped
		expect(body.top_k).toBe(5);
		expect(hits).toEqual([
			{ index: 1, score: 0.9 },
			{ index: 0, score: 0.2 },
		]);
	});

	it("no-ops on an empty passage list without calling fetch", async () => {
		const client = createEmbedClient();
		expect(await client.rerank("q", [])).toEqual([]);
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

describe("error handling", () => {
	beforeEach(() => {
		process.env.SHOR_EMBED_URL = "https://embed.local";
	});

	it("throws EmbedError with status on a non-2xx response", async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse({}, false, 503));
		const client = createEmbedClient();
		await expect(client.embedText(["x"])).rejects.toMatchObject({
			name: "EmbedError",
			status: 503,
		});
	});

	it("wraps a transport failure in EmbedError", async () => {
		fetchMock.mockRejectedValueOnce(new Error("ECONNREFUSED"));
		const client = createEmbedClient();
		await expect(client.embedCode(["x"])).rejects.toBeInstanceOf(EmbedError);
	});
});
