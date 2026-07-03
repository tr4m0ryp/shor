// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * HTTP client for the self-hosted embed/rerank model server (infra/embedder).
 *
 * Endpoints (see infra/embedder/README.md for the wire contract):
 *   POST `${SHOR_EMBED_URL}/embed/code`  -> codesage-large-v2 (truncated 1024)
 *   POST `${SHOR_EMBED_URL}/embed/text`  -> gte-large-en-v1.5 / bge-m3 (1024)
 *   POST `${SHOR_EMBED_URL}/rerank`      -> bge-reranker-v2-m3 cross-encoder
 * Optional `Authorization: Bearer ${SHOR_EMBED_TOKEN}`.
 *
 * Default-off: with `SHOR_EMBED_URL` unset the factory returns a no-op client
 * (`enabled === false`) that makes no network calls, so a stock scan is
 * unchanged. On a genuine transport/HTTP failure of a configured server the
 * client THROWS `EmbedError` (never silently drops embeddings).
 */

import type {
	EmbedClient,
	EmbedClientConfig,
	EmbedOptions,
	EmbedResult,
	RerankHit,
	RerankOptions,
} from "./types.js";

/** Hard cap on candidates sent to the reranker (spec T4: ~50). */
export const MAX_RERANK = 50;

const CODE_PATH = "/embed/code";
const TEXT_PATH = "/embed/text";
const RERANK_PATH = "/rerank";

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_BATCH = 64;
const DEFAULT_CODE_DIM = 1024;

/** Thrown when a configured server is unreachable or returns a non-2xx. */
export class EmbedError extends Error {
	readonly status: number | undefined;
	constructor(message: string, status?: number) {
		super(message);
		this.name = "EmbedError";
		this.status = status;
	}
}

/**
 * Read embed/rerank config from env; `undefined` (=> no-op client) when
 * `SHOR_EMBED_URL` is unset. `SHOR_EMBED_TOKEN` is optional bearer auth.
 */
export function readEmbedConfig(): EmbedClientConfig | undefined {
	const baseUrl = process.env.SHOR_EMBED_URL?.trim();
	if (!baseUrl) return undefined;
	const token = process.env.SHOR_EMBED_TOKEN?.trim();
	const cfg: EmbedClientConfig = { baseUrl: baseUrl.replace(/\/+$/, "") };
	if (token) cfg.token = token;
	return cfg;
}

function emptyResult(): EmbedResult {
	return { model: "", dim: 0, embeddings: [], tokenCounts: [] };
}

function buildHeaders(cfg: EmbedClientConfig): Record<string, string> {
	const headers: Record<string, string> = { "content-type": "application/json" };
	if (cfg.token) headers.authorization = `Bearer ${cfg.token}`;
	return headers;
}

async function postJson<T>(
	cfg: EmbedClientConfig,
	path: string,
	body: unknown,
	signal?: AbortSignal,
): Promise<T> {
	const url = `${cfg.baseUrl}${path}`;
	const controllerSignal =
		signal ?? AbortSignal.timeout(cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS);
	let res: Response;
	try {
		res = await fetch(url, {
			method: "POST",
			headers: buildHeaders(cfg),
			body: JSON.stringify(body),
			signal: controllerSignal,
		});
	} catch (err) {
		const detail = err instanceof Error ? err.message : String(err);
		throw new EmbedError(`embed request to ${path} failed: ${detail}`);
	}
	if (!res.ok) {
		throw new EmbedError(`embed ${path} returned HTTP ${res.status}`, res.status);
	}
	return (await res.json()) as T;
}

function chunk<T>(items: T[], size: number): T[][] {
	if (items.length === 0) return [];
	if (items.length <= size) return [items];
	const out: T[][] = [];
	for (let i = 0; i < items.length; i += size) {
		out.push(items.slice(i, i + size));
	}
	return out;
}

interface EmbedWire {
	model: string;
	dim: number;
	embeddings: number[][];
	token_counts?: number[];
}

interface RerankWire {
	model: string;
	results: RerankHit[];
}

async function embed(
	cfg: EmbedClientConfig,
	path: string,
	texts: string[],
	opts: EmbedOptions | undefined,
): Promise<EmbedResult> {
	if (texts.length === 0) return emptyResult();
	const batchSize = cfg.batchSize ?? DEFAULT_BATCH;
	const normalize = opts?.normalize ?? true;
	const merged = emptyResult();
	for (const batch of chunk(texts, batchSize)) {
		const body: Record<string, unknown> = { inputs: batch, normalize };
		if (path === CODE_PATH) {
			body.truncate_dim = opts?.truncateDim ?? DEFAULT_CODE_DIM;
		}
		const wire = await postJson<EmbedWire>(cfg, path, body, opts?.signal);
		merged.model = wire.model;
		merged.dim = wire.dim;
		merged.embeddings.push(...wire.embeddings);
		merged.tokenCounts.push(...(wire.token_counts ?? []));
	}
	return merged;
}

async function rerank(
	cfg: EmbedClientConfig,
	query: string,
	passages: string[],
	opts: RerankOptions | undefined,
): Promise<RerankHit[]> {
	if (passages.length === 0) return [];
	const capped = passages.slice(0, MAX_RERANK);
	const body: Record<string, unknown> = { query, passages: capped };
	if (opts?.topK !== undefined) {
		body.top_k = Math.min(opts.topK, capped.length);
	}
	const wire = await postJson<RerankWire>(cfg, RERANK_PATH, body, opts?.signal);
	return wire.results;
}

/**
 * Build an embed/rerank client. Pass an explicit config, or omit to read env
 * via {@link readEmbedConfig}. When no config resolves, returns a no-op client.
 */
export function createEmbedClient(config?: EmbedClientConfig): EmbedClient {
	const cfg = config ?? readEmbedConfig();
	if (!cfg) {
		return {
			enabled: false,
			async embedCode() {
				return emptyResult();
			},
			async embedText() {
				return emptyResult();
			},
			async rerank() {
				return [];
			},
		};
	}
	return {
		enabled: true,
		embedCode: (texts, opts) => embed(cfg, CODE_PATH, texts, opts),
		embedText: (texts, opts) => embed(cfg, TEXT_PATH, texts, opts),
		rerank: (query, passages, opts) => rerank(cfg, query, passages, opts),
	};
}
