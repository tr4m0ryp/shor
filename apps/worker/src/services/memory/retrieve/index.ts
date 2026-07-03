// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Two-tier hybrid retrieval — public surface (task 012, spec T4/F5/F13).
 *
 * The "recall" half of the learning-memory loop, run BEFORE analysis. For a
 * query it recalls exemplars from BOTH tiers (project-local + cross-tenant
 * global), fuses per-tier by hybrid RRF, fuses across tiers by weighted RRF
 * (local > global), reranks with the cross-encoder, and renders the top 5-8 into
 * the `{{RAG_EXEMPLARS}}` prompt include.
 *
 * Flag-gated / default-OFF: retrieval runs only when `SHOR_MEMORY_RETRIEVE` is
 * enabled AND an embed server is configured (`SHOR_EMBED_URL`, via
 * `deps.embed.enabled`). Otherwise, and on any embed/store failure, it returns
 * nothing and `rendered` is `null` — the prompt is unchanged. The assembler then
 * leaves `context.ragExemplars` unset, which renders as the "(none)" sentinel.
 *
 * Usage (wired by the prompt-context assembler):
 *   const { rendered } = await retrieveExemplars(query, scope, {
 *     embed: createEmbedClient(),
 *     local: findingEmbeddingRepo, // structural port
 *     global: globalPoolRepo,      // structural port
 *   });
 *   if (rendered) context.ragExemplars = rendered;
 */

import { tokenizeCode } from "./bm25.js";
import { fuseAndRerank, renderInclude } from "./fuse.js";
import { fuseTier, recallGlobal, recallLocal } from "./hybrid.js";
import type {
	RetrievalQuery,
	RetrievalScope,
	RetrieveDeps,
	RetrieveResult,
} from "./types.js";

/** True when `SHOR_MEMORY_RETRIEVE` is truthy (`1`/`true`/`yes`/`on`). */
export function readMemoryRetrieveEnabled(
	env: NodeJS.ProcessEnv = process.env,
): boolean {
	const raw = env["SHOR_MEMORY_RETRIEVE"]?.trim().toLowerCase();
	return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

const EMPTY: RetrieveResult = { exemplars: [], rendered: null };

/** BM25 query terms: the semantic text plus any explicit identifier hints. */
export function buildQueryTerms(query: RetrievalQuery): string[] {
	const terms = tokenizeCode(query.text);
	if (query.cwe) terms.push(...tokenizeCode(query.cwe));
	if (query.terms) {
		for (const t of query.terms) terms.push(...tokenizeCode(t));
	}
	return terms;
}

/** Extract a usable vector from an embed result, or null when absent/empty. */
function firstVector(res: {
	dim: number;
	embeddings: number[][];
}): number[] | null {
	if (res.dim <= 0) return null;
	const vec = res.embeddings[0];
	return vec && vec.length > 0 ? vec : null;
}

/**
 * Retrieve the top 5-8 past-vulnerability exemplars for `query`, scoped to
 * `scope`, and render them for the `{{RAG_EXEMPLARS}}` include. Default-off and
 * fail-open: a disabled store or any embed/recall failure returns {@link EMPTY}
 * (prompt unchanged) rather than throwing into the scan pipeline.
 */
export async function retrieveExemplars(
	query: RetrievalQuery,
	scope: RetrievalScope,
	deps: RetrieveDeps,
): Promise<RetrieveResult> {
	const enabled = deps.enabled ?? readMemoryRetrieveEnabled();
	if (!enabled || !deps.embed.enabled || query.text.trim() === "") return EMPTY;

	const cfg = deps.config ?? {};
	try {
		// 1. Embed the query (text always; code when the caller supplies a snippet).
		const textRes = await deps.embed.embedText([query.text]);
		const vecText = firstVector(textRes);
		let vecCode: number[] | null = null;
		if (query.code && query.code.trim() !== "") {
			const codeRes = await deps.embed.embedCode([query.code]);
			vecCode = firstVector(codeRes);
		}
		if (!vecText && !vecCode) return EMPTY;

		// 2. Per-tier hybrid recall — ALWAYS query both tiers (spec T4).
		const recallOpts = cfg.recall !== undefined ? { recall: cfg.recall } : {};
		const [localRecall, globalRecall] = await Promise.all([
			recallLocal(deps.local, scope, vecText, vecCode, {
				...recallOpts,
				cwe: query.cwe ?? null,
			}),
			recallGlobal(deps.global, vecText, vecCode, recallOpts),
		]);

		const queryTerms = buildQueryTerms(query);
		const tierOpts = {
			...(cfg.rrfK !== undefined && { k: cfg.rrfK }),
			...(cfg.recall !== undefined && { recall: cfg.recall }),
		};
		const localRanked = fuseTier(localRecall, queryTerms, tierOpts);
		const globalRanked = fuseTier(globalRecall, queryTerms, tierOpts);

		// 3. Weighted cross-tier fusion + rerank -> top 5-8.
		const exemplars = await fuseAndRerank(localRanked, globalRanked, {
			embed: deps.embed,
			queryText: query.text,
			...(cfg.localWeight !== undefined && { localWeight: cfg.localWeight }),
			...(cfg.rrfK !== undefined && { k: cfg.rrfK }),
			...(cfg.topK !== undefined && { topK: cfg.topK }),
			logger: deps.logger,
		});

		return { exemplars, rendered: renderInclude(exemplars) };
	} catch (err) {
		deps.logger?.error("rag-retrieve: failed — prompt left unchanged", {
			reason: err instanceof Error ? err.message : String(err),
		});
		return EMPTY;
	}
}

export type {
	ExemplarCandidate,
	GlobalKind,
	GlobalTierMatch,
	GlobalTierPort,
	LocalTierMatch,
	LocalTierPort,
	RagExemplar,
	RetrievalQuery,
	RetrievalScope,
	RetrieveConfig,
	RetrieveDeps,
	RetrieveResult,
	VecColumn,
} from "./types.js";
export { renderInclude, weightedCrossTierRrf } from "./fuse.js";
export { fuseTier, recallGlobal, recallLocal, rrf } from "./hybrid.js";
