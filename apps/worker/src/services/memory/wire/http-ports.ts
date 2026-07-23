// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * HTTP-backed adapters that satisfy the memory ports structurally, so the
 * worker's retrieve/write logic runs unchanged against the pgvector store in
 * apps/web. Each method is one authenticated POST to a thin `/scans/:id/memory/*`
 * route; the web side derives the tenant/project from the scan (never trusting
 * the worker-supplied scope) and runs the actual `nearest` / insert.
 *
 * Reads (`nearest`) and writes (`create`/`upsert`) both flow here. Transport
 * failures throw — the callers (retrieve-rag / persist-rag) wrap them fail-open
 * so a store hiccup never breaks a scan.
 */

import type {
	GlobalKind,
	GlobalTierMatch,
	GlobalTierPort,
	LocalTierMatch,
	LocalTierPort,
	RetrievalScope,
	VecColumn,
} from "../retrieve/types.js";
import type {
	FindingEmbeddingWriter,
	FpMemoryWriter,
} from "../write/persist.js";
import type { MemoryWireConfig } from "./config.js";

const DEFAULT_TIMEOUT_MS = 20_000;

/** POST JSON to a `/scans/:id/memory/<path>` route; throws on non-2xx. */
async function post<T>(
	cfg: MemoryWireConfig,
	path: string,
	body: unknown,
): Promise<T> {
	const res = await fetch(`${cfg.baseUrl}/${path}`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			authorization: `Bearer ${cfg.token}`,
		},
		body: JSON.stringify(body),
		signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
	});
	if (!res.ok) {
		throw new Error(`memory ${path} returned HTTP ${res.status}`);
	}
	return (await res.json()) as T;
}

/** Local-tier `nearest` over HTTP (project-scoped ANN, RLS enforced web-side). */
export function createHttpLocalPort(cfg: MemoryWireConfig): LocalTierPort {
	return {
		async nearest(
			_scope: RetrievalScope,
			query: readonly number[],
			opts?: { column?: VecColumn; limit?: number; cwe?: string | null },
		): Promise<readonly LocalTierMatch[]> {
			const { matches } = await post<{ matches: LocalTierMatch[] }>(
				cfg,
				"nearest",
				{
					tier: "local",
					column: opts?.column ?? "vec_text",
					vector: query,
					limit: opts?.limit,
					cwe: opts?.cwe ?? null,
				},
			);
			return matches;
		},
	};
}

/** Global-tier (cross-tenant) `nearest` over HTTP. */
export function createHttpGlobalPort(cfg: MemoryWireConfig): GlobalTierPort {
	return {
		async nearest(
			query: readonly number[],
			opts?: { column?: VecColumn; limit?: number; kind?: GlobalKind | null },
		): Promise<readonly GlobalTierMatch[]> {
			const { matches } = await post<{ matches: GlobalTierMatch[] }>(
				cfg,
				"nearest",
				{
					tier: "global",
					column: opts?.column ?? "vec_text",
					vector: query,
					limit: opts?.limit,
					kind: opts?.kind ?? null,
				},
			);
			return matches;
		},
	};
}

/** Local-tier `finding_embedding` insert over HTTP (the write path's port). */
export function createHttpEmbeddingWriter(
	cfg: MemoryWireConfig,
): FindingEmbeddingWriter {
	return {
		async create(input): Promise<{ id: string }> {
			return post<{ id: string }>(cfg, "embeddings", {
				kind: "embedding",
				...input,
			});
		},
	};
}

/** `fp_memory` upsert over HTTP (the write path's false-positive port). */
export function createHttpFpMemoryWriter(cfg: MemoryWireConfig): FpMemoryWriter {
	return {
		async upsert(input): Promise<{ id: string }> {
			return post<{ id: string }>(cfg, "embeddings", {
				kind: "fp",
				...input,
			});
		},
	};
}
