// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Ingest seed exemplars into the shared cross-tenant `global_pool` as `exemplar`
 * rows. Mirrors the promote path (task 014): verbalize -> embed -> insert. The
 * writer is an INJECTED PORT (`GlobalPoolWriter`) — the worker never imports
 * `pg`; the CLI wires a concrete writer.
 *
 * Why no scrub gate here (unlike task 014): seeds are PUBLIC research, not client
 * data, and are written with `sourceTenant: null`. That null provenance is what
 * sidesteps the cross-tenant consent gate — there is no tenant whose data is
 * being pooled, so there is nothing to consent to and no secret/PII to quarantine
 * (the exemplars are authored, not captured). Retrieval still needs vectors, so
 * this is a clean no-op when the embed server is disabled.
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";
import type { EmbedClient } from "../embed/index.js";
import type { GlobalPoolWriter, SeedExemplar, Vector } from "./types.js";
import { verbalizeSeed } from "./verbalize.js";

/** Injected collaborators for {@link seedGlobalPool}. */
export interface SeedIngestDeps {
	readonly embed: EmbedClient;
	readonly writer: GlobalPoolWriter;
	readonly logger?: ActivityLogger | undefined;
}

/** Why ingest wrote nothing (a clean, non-error skip). */
export type SeedSkipReason = "embed_disabled" | "empty";

/** Outcome of a seed ingest run. */
export interface SeedIngestResult {
	/** Number of `exemplar` rows written. */
	readonly seeded: number;
	/** Exemplars not written (duplicates, or all when skipped). */
	readonly skipped: number;
	/** Present only when the whole run was a clean no-op. */
	readonly reason?: SeedSkipReason;
	/** Pool row ids, in write order. */
	readonly poolIds: readonly string[];
}

/** Stable dedupe key: prefer the CAPEC id, else technique + data-flow source. */
export function seedKey(unit: SeedExemplar): string {
	const capec = unit.capecId?.trim().toLowerCase();
	if (capec) return `capec:${capec}`;
	return `t:${unit.technique.trim().toLowerCase()}::${unit.source.trim().toLowerCase()}`;
}

/** Drop later duplicates by {@link seedKey}, preserving first-seen order. */
function dedupe(units: readonly SeedExemplar[]): SeedExemplar[] {
	const seen = new Set<string>();
	const out: SeedExemplar[] = [];
	for (const unit of units) {
		const key = seedKey(unit);
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(unit);
	}
	return out;
}

/** Build the pool payload: all structured fields + the `seeded` marker. */
function buildPayload(unit: SeedExemplar): Record<string, unknown> {
	return { ...unit, seeded: true };
}

/**
 * Verbalize + embed + insert each unique seed exemplar as a public `exemplar`
 * row (`sourceTenant: null`). Skips cleanly (no writes) when the embed client is
 * disabled or the input is empty. Text embeds Vector A (the verbalized doc); the
 * PoC skeleton embeds Vector B when present. One insert per exemplar so a single
 * writer failure surfaces without a partial-batch ambiguity.
 */
export async function seedGlobalPool(
	units: readonly SeedExemplar[],
	deps: SeedIngestDeps,
): Promise<SeedIngestResult> {
	const unique = dedupe(units);
	if (unique.length === 0) {
		return { seeded: 0, skipped: 0, reason: "empty", poolIds: [] };
	}
	if (!deps.embed.enabled) {
		deps.logger?.info("seed-ingest: embed disabled — nothing written", {
			candidates: unique.length,
		});
		return {
			seeded: 0,
			skipped: unique.length,
			reason: "embed_disabled",
			poolIds: [],
		};
	}

	const verbs = unique.map(verbalizeSeed);

	// Vector A — one batched text embed for the whole set.
	const textRes = await deps.embed.embedText(verbs.map((v) => v.text));

	// Vector B — embed only the non-empty PoC skeletons, mapped back by index.
	const codeIndices: number[] = [];
	const codeTexts: string[] = [];
	verbs.forEach((v, i) => {
		if (v.codeText) {
			codeIndices.push(i);
			codeTexts.push(v.codeText);
		}
	});
	const codeByIndex = new Map<number, Vector>();
	if (codeTexts.length > 0) {
		const codeRes = await deps.embed.embedCode(codeTexts);
		codeIndices.forEach((origIndex, j) => {
			const vec = codeRes.embeddings[j];
			if (vec) codeByIndex.set(origIndex, vec);
		});
	}

	const poolIds: string[] = [];
	for (let i = 0; i < unique.length; i++) {
		const unit = unique[i] as SeedExemplar;
		const vecText: Vector | null = textRes.embeddings[i] ?? null;
		const vecCode: Vector | null = codeByIndex.get(i) ?? null;
		const row = await deps.writer.insert({
			kind: "exemplar",
			payload: buildPayload(unit),
			vecText,
			vecCode,
			sourceTenant: null,
		});
		poolIds.push(row.id);
	}

	deps.logger?.info("seed-ingest: exemplars written to global pool", {
		seeded: poolIds.length,
		duplicatesDropped: units.length - unique.length,
	});
	return {
		seeded: poolIds.length,
		skipped: units.length - unique.length,
		poolIds,
	};
}
