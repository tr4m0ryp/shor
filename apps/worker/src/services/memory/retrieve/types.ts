// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Public types for two-tier hybrid retrieval (spec T4 / F13).
 *
 * The retriever fuses two corpora before analysis: the project-LOCAL tier
 * (`finding_embedding`, RLS-scoped) and the cross-tenant GLOBAL tier
 * (`global_pool`). Both are reached through injected PORTS — the worker package
 * does not depend on `pg`/apps-web, exactly like the write path
 * (`../write/persist.ts`). The real `findingEmbeddingRepo.nearest` /
 * `globalPoolRepo.nearest` (apps/web) satisfy these ports structurally; tests
 * pass fakes.
 *
 * The store persists ONLY embeddings + structured columns (no verbalized doc
 * text column, see 0008_memory.sql), so the sparse/BM25 half ranks on the
 * exact-identifier columns a candidate carries (T3: "exact-identifier BM25").
 */

import type { EmbedClient } from "../embed/index.js";
import type { ActivityLogger } from "../../../types/activity-logger.js";

/** Which dense column an ANN query ranks on (mirrors the repo `VecColumn`). */
export type VecColumn = "vec_code" | "vec_text";

/** Global-pool item role (mirrors the repo `GlobalPoolKind`). */
export type GlobalKind = "abstraction" | "exemplar" | "finding";

/** Tenant/project scope for a retrieval (drives RLS on the local tier). */
export interface RetrievalScope {
	readonly tenantId: string;
	/** Omit for a tenant-wide read; normally the project under scan. */
	readonly projectId?: string | null;
}

/**
 * A local-tier ANN hit — the structural subset of `FindingEmbeddingMatch`
 * (apps/web) the retriever consumes. Every field here is present on the real
 * match, so the real repo is assignable to {@link LocalTierPort}.
 */
export interface LocalTierMatch {
	readonly id: string;
	/** pgvector cosine distance (`<=>`); smaller = nearer. */
	readonly distance: number;
	readonly cwe: string | null;
	readonly vulnClass: string | null;
	readonly severity: string | null;
	readonly route: string | null;
	readonly source: string | null;
	readonly sink: string | null;
	readonly componentVer: string | null;
	readonly confidence: string | null;
}

/**
 * A global-tier ANN hit — the structural subset of `GlobalPoolMatch`
 * (apps/web). The global table has no structured identifier columns; a pooled
 * item's metadata lives inside its JSONB `payload`, so the retriever extracts
 * identifiers/text from there.
 */
export interface GlobalTierMatch {
	readonly id: string;
	readonly distance: number;
	readonly kind: string;
	readonly payload: Record<string, unknown>;
}

/** Injected local-tier port (real: `findingEmbeddingRepo.nearest`). */
export interface LocalTierPort {
	nearest(
		scope: RetrievalScope,
		query: readonly number[],
		opts?: { column?: VecColumn; limit?: number; cwe?: string | null },
	): Promise<readonly LocalTierMatch[]>;
}

/** Injected global-tier port (real: `globalPoolRepo.nearest`). */
export interface GlobalTierPort {
	nearest(
		query: readonly number[],
		opts?: { column?: VecColumn; limit?: number; kind?: GlobalKind | null },
	): Promise<readonly GlobalTierMatch[]>;
}

/**
 * A tier-normalized candidate. Local hits map their structured columns
 * directly; global hits project their `payload` onto the same shape (+ `text`
 * when the payload carries a verbalized doc/summary).
 */
export interface ExemplarCandidate {
	/** Namespaced id (`local:<id>` / `global:<id>`) — unique across tiers. */
	readonly key: string;
	readonly tier: "local" | "global";
	readonly id: string;
	readonly distance: number;
	readonly cwe: string | null;
	readonly vulnClass: string | null;
	readonly severity: string | null;
	readonly route: string | null;
	readonly source: string | null;
	readonly sink: string | null;
	readonly componentVer: string | null;
	readonly confidence: string | null;
	/** Optional richer text (a global payload doc/summary), for rerank + render. */
	readonly text: string | null;
}

/** The semantic + structured query that seeds retrieval. */
export interface RetrievalQuery {
	/** Semantic query text (verbalized context / candidate finding doc). */
	readonly text: string;
	/** Optional code snippet — enables the `vec_code` dense channel. */
	readonly code?: string | null;
	/** Optional CWE pre-filter for the local B-tree; also a lexical term. */
	readonly cwe?: string | null;
	/** Optional extra identifier terms (route/source/sink) for the BM25 half. */
	readonly terms?: readonly string[];
}

/** Tunable knobs; every field defaults inside the retriever. */
export interface RetrieveConfig {
	/** Cross-tier local weight (spec: 1.3-1.5x global). Clamped to [1.3, 1.5]. */
	readonly localWeight?: number;
	/** RRF constant (spec T4: 60). */
	readonly rrfK?: number;
	/** Per-tier hybrid recall depth (spec: 20-30). */
	readonly recall?: number;
	/** Final exemplar count handed to DeepSeek (spec: 5-8). Clamped to [5, 8]. */
	readonly topK?: number;
}

/** Injected collaborators for {@link retrieveExemplars}. */
export interface RetrieveDeps {
	readonly embed: EmbedClient;
	readonly local: LocalTierPort;
	readonly global: GlobalTierPort;
	readonly logger?: ActivityLogger | undefined;
	/** Override the `SHOR_MEMORY_RETRIEVE` env gate (mainly for tests). */
	readonly enabled?: boolean | undefined;
	readonly config?: RetrieveConfig | undefined;
}

/** A final ranked exemplar plus its one-line rendering for the prompt include. */
export interface RagExemplar {
	readonly candidate: ExemplarCandidate;
	/** Cross-encoder rerank score when reranked, else the fused RRF score. */
	readonly score: number;
	/** The rendered bullet line injected into `{{RAG_EXEMPLARS}}`. */
	readonly line: string;
}

/** Result of a retrieval: the ranked exemplars + the ready include string. */
export interface RetrieveResult {
	readonly exemplars: readonly RagExemplar[];
	/**
	 * The `{{RAG_EXEMPLARS}}` block, or `null` when nothing was retrieved (the
	 * caller then leaves `context.ragExemplars` unset -> "(none)" sentinel).
	 */
	readonly rendered: string | null;
}
