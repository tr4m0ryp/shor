// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Public types for the embed/rerank client (spec T5 / F13).
 *
 * The client is the single seam all downstream RAG tasks (011 verbalized
 * finding, 012 retrieval, 013) call to embed code + text and rerank passages.
 * It is default-off: unset `SHOR_EMBED_URL` yields a no-op client.
 */

/** Which embedding space a request targets. */
export type EmbedSpace = "code" | "text";

/** Resolved connection config for the embed/rerank model server. */
export interface EmbedClientConfig {
	/** Base URL of the model server (no trailing slash). */
	baseUrl: string;
	/** Optional bearer token (`SHOR_EMBED_TOKEN`). */
	token?: string;
	/** Per-request network timeout in ms. Default 30000. */
	timeoutMs?: number;
	/** Max inputs per HTTP call; longer arrays are chunked. Default 64. */
	batchSize?: number;
}

/** Options for an embed call. */
export interface EmbedOptions {
	/**
	 * L2-normalize server-side so the pgvector store receives unit vectors.
	 * Default true (the store expects normalized embeddings).
	 */
	normalize?: boolean;
	/**
	 * Matryoshka truncation dim for CODE embeddings (codesage is 2048-native,
	 * truncated to the store's 1024). Ignored for text. Default 1024.
	 */
	truncateDim?: number;
	/** Abort signal; overrides the config timeout when provided. */
	signal?: AbortSignal;
}

/**
 * Result of an embed call. `tokenCounts[i]` is the model token length of
 * `inputs[i]` — the "length hint" a caller (task 011 late-chunking) uses to
 * decide whether to chunk a snippet before embedding.
 */
export interface EmbedResult {
	/** HuggingFace id of the model that produced the vectors. */
	model: string;
	/** Dimensionality of each embedding (0 when the client is disabled). */
	dim: number;
	/** One vector per input, in input order. */
	embeddings: number[][];
	/** Per-input model token count (length hint). */
	tokenCounts: number[];
}

/** A single reranked passage, referenced by its original index. */
export interface RerankHit {
	/** Index into the `passages` array passed to `rerank`. */
	index: number;
	/** Cross-encoder relevance score (higher = more relevant). */
	score: number;
}

/** Options for a rerank call. */
export interface RerankOptions {
	/** Return only the top-k hits (hard-capped by the server input cap). */
	topK?: number;
	/** Abort signal; overrides the config timeout when provided. */
	signal?: AbortSignal;
}

/** The public embed/rerank surface consumed by tasks 011/012/013. */
export interface EmbedClient {
	/** True only when `SHOR_EMBED_URL` is configured. */
	readonly enabled: boolean;
	/** Embed code snippets (codesage-large-v2, truncated to 1024-dim). */
	embedCode(texts: string[], opts?: EmbedOptions): Promise<EmbedResult>;
	/** Embed verbalized/finding text (gte-large-en-v1.5 or bge-m3, 1024-dim). */
	embedText(texts: string[], opts?: EmbedOptions): Promise<EmbedResult>;
	/** Rerank passages against a query (bge-reranker-v2-m3 cross-encoder). */
	rerank(
		query: string,
		passages: string[],
		opts?: RerankOptions,
	): Promise<RerankHit[]>;
}
