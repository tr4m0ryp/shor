// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Deterministic Joern-output -> observation parsing + the second-order JOIN.
 *
 * This is the part of the driver that must be sound and testable WITHOUT a Joern
 * install: given the raw JSON the generated script emits, it (a) turns direct
 * flows into observations and (b) BRIDGES the persistence boundary — pairing a
 * "tainted input reached a write to store X" flow with a "value read from store
 * X reached a sink" flow to synthesize a `second_order` observation. That bridge
 * is the through-step model that lets us catch stored/second-order flows Joern
 * (and every static engine) would otherwise miss.
 *
 * Kept pure so the store-join is unit-tested against representative payloads.
 */

import { createHash } from "node:crypto";
import type {
	JoernFlow,
	JoernRawResult,
	TaintConfidence,
	TaintLanguage,
	TaintObservation,
	TaintPathStep,
} from "../types.js";
import { confidenceForLanguage } from "../specs/defaults.js";

/** Per-bucket flow cap so a pathological CPG can't explode observation count. */
export const MAX_FLOWS_PER_BUCKET = 25;

/** Coerce the script's language string back to our enum (defaults to unknown). */
export function toTaintLanguage(raw: string): TaintLanguage {
	const known: TaintLanguage[] = [
		"java",
		"javascript",
		"typescript",
		"python",
		"go",
		"c",
	];
	return (known as string[]).includes(raw) ? (raw as TaintLanguage) : "unknown";
}

/** Stable 16-hex id over the identifying fields (deterministic correlation key). */
function observationId(parts: readonly (string | number | undefined)[]): string {
	const key = parts.map((p) => (p === undefined ? "" : String(p))).join("|");
	return createHash("sha1").update(key).digest("hex").slice(0, 16);
}

function locKey(s: TaintPathStep): string {
	return `${s.file ?? ""}:${s.line ?? ""}`;
}

/** Direct source->sink flows for one vuln class -> observations. */
function directObservations(
	buckets: JoernRawResult["direct"],
	lang: TaintLanguage,
	confidence: TaintConfidence,
): TaintObservation[] {
	const out: TaintObservation[] = [];
	for (const bucket of buckets) {
		for (const flow of bucket.flows.slice(0, MAX_FLOWS_PER_BUCKET)) {
			out.push({
				id: observationId([
					"direct",
					bucket.vulnClass,
					locKey(flow.source),
					locKey(flow.sink),
				]),
				flowKind: "direct",
				vulnClass: bucket.vulnClass,
				cwe: bucket.cwe,
				source: flow.source,
				sink: flow.sink,
				steps: flow.path,
				confidence,
				language: lang,
				engine: "joern",
			});
		}
	}
	return out;
}

/** Synthetic path element marking the persistence hop between the two halves. */
function storeMarker(store: string): TaintPathStep {
	return { method: `store:${store}`, code: `<< value persisted to ${store} >>` };
}

/** Stitch a source->write flow and a read->sink flow into one path list. */
function bridgePath(toFlow: JoernFlow, store: string, fromFlow: JoernFlow): TaintPathStep[] {
	return [...toFlow.path, storeMarker(store), ...fromFlow.path];
}

/**
 * The through-step JOIN: for every store that has BOTH a tainted-input->write
 * flow (`toStore`) and a read->sink flow (`fromStore`), emit a `second_order`
 * observation. The write flow supplies the entry (source + how taint reached the
 * store); the read flow supplies the exit (which sink the stored value reaches).
 */
export function secondOrderObservations(
	raw: JoernRawResult,
	lang: TaintLanguage,
	confidence: TaintConfidence,
): TaintObservation[] {
	const out: TaintObservation[] = [];
	for (const to of raw.toStore) {
		// The representative proof that untrusted input reaches this store.
		const entry = to.flows[0];
		if (!entry) continue;
		const froms = raw.fromStore.filter((f) => f.store === to.store);
		for (const from of froms) {
			const vulnClass = from.vulnClass ?? "stored_taint";
			for (const fFlow of from.flows.slice(0, MAX_FLOWS_PER_BUCKET)) {
				out.push({
					id: observationId([
						"second_order",
						to.store,
						vulnClass,
						locKey(entry.source),
						locKey(fFlow.sink),
					]),
					flowKind: "second_order",
					vulnClass,
					cwe: from.cwe,
					source: entry.source,
					sink: fFlow.sink,
					steps: bridgePath(entry, to.store, fFlow),
					throughStore: to.store,
					confidence,
					language: lang,
					engine: "joern",
				});
			}
		}
	}
	return out;
}

/** Full parse: direct observations + the second-order through-step join. */
export function parseObservations(raw: JoernRawResult): TaintObservation[] {
	const lang = toTaintLanguage(raw.language);
	const confidence = confidenceForLanguage(lang);
	return [
		...directObservations(raw.direct, lang, confidence),
		...secondOrderObservations(raw, lang, confidence),
	];
}
