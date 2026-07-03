// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * The sparse (lexical) half of the hybrid ranker (spec T4, F5).
 *
 * The store persists no verbalized doc text (0008_memory.sql keeps only the
 * embedding + structured identifier columns), and the repositories expose only a
 * dense `nearest` seam — there is no `tsvector` column or `ts_rank` repo method
 * to call, and adding one is migration/task-001 scope, out of scope here. So the
 * BM25 channel runs clean-room, IN-WORKER, over the identifier columns each
 * recalled candidate carries ("exact-identifier BM25", T3): a code-aware
 * tokenizer (keeps `$`, `_`, `.`, `/`, `->` carriers so `$_GET`, `req.body`,
 * `db->query` survive) feeding Okapi BM25 (k1=1.5, b=0.75) scored across the
 * recalled candidate set. Pure + deterministic.
 */

/** Okapi BM25 term-frequency saturation. */
const K1 = 1.5;
/** Okapi BM25 length normalization. */
const B = 0.75;

/**
 * A code-aware tokenizer. Lowercases, then emits identifier runs while KEEPING
 * the carriers that distinguish code tokens (`$ _ . / : -> #`), and ALSO emits
 * the sub-identifiers of a compound (splitting on `. / -> ::`) so
 * `req.body.id` matches both the whole path and `body`/`id`. De-duplication is
 * left to the caller (raw multiplicity feeds term frequency).
 */
export function tokenizeCode(input: string | null | undefined): string[] {
	if (!input) return [];
	const lower = input.toLowerCase();
	const tokens: string[] = [];
	// A compound identifier: word chars + the code carriers.
	const compoundRe = /[a-z0-9_$][a-z0-9_$.:/#>-]*/g;
	for (const match of lower.matchAll(compoundRe)) {
		const whole = match[0].replace(/[.:/#>-]+$/g, "");
		if (whole.length === 0) continue;
		tokens.push(whole);
		// Sub-identifiers of a dotted/pathed/arrow compound.
		if (/[.:/>-]/.test(whole)) {
			for (const part of whole.split(/[.:/#>-]+/g)) {
				if (part.length > 1 && part !== whole) tokens.push(part);
			}
		}
	}
	return tokens;
}

/** A tokenized candidate document plus its length (token count). */
export interface LexicalDoc {
	readonly key: string;
	readonly terms: string[];
	readonly length: number;
}

/** Tokenize one candidate's identifier fields into a {@link LexicalDoc}. */
export function toLexicalDoc(key: string, fields: readonly (string | null)[]): LexicalDoc {
	const terms: string[] = [];
	for (const field of fields) {
		if (field) terms.push(...tokenizeCode(field));
	}
	return { key, terms, length: terms.length };
}

/** Per-document term-frequency map (built once per scoring pass). */
function termFrequencies(terms: readonly string[]): Map<string, number> {
	const tf = new Map<string, number>();
	for (const t of terms) tf.set(t, (tf.get(t) ?? 0) + 1);
	return tf;
}

/**
 * Rank `docs` against `queryTerms` by Okapi BM25, returning candidate keys
 * ordered best-first. Documents with a zero score (no query term present) are
 * dropped — they add nothing to the lexical channel. IDF and average length are
 * computed across the supplied candidate set (the recall pool).
 */
export function bm25Rank(
	queryTerms: readonly string[],
	docs: readonly LexicalDoc[],
): string[] {
	if (docs.length === 0 || queryTerms.length === 0) return [];
	const query = Array.from(new Set(queryTerms));
	const n = docs.length;
	const avgdl = docs.reduce((s, d) => s + d.length, 0) / n || 1;

	// Document frequency per query term (how many docs contain it).
	const df = new Map<string, number>();
	const docTf = docs.map((d) => termFrequencies(d.terms));
	for (const term of query) {
		let count = 0;
		for (const tf of docTf) if (tf.has(term)) count++;
		df.set(term, count);
	}

	const scored = docs.map((doc, i) => {
		const tf = docTf[i] as Map<string, number>;
		let score = 0;
		for (const term of query) {
			const f = tf.get(term);
			if (!f) continue;
			const n_q = df.get(term) ?? 0;
			// BM25 IDF with the +0.5 smoothing; floored at 0 so a term present in
			// every candidate cannot push the score negative.
			const idf = Math.max(0, Math.log(1 + (n - n_q + 0.5) / (n_q + 0.5)));
			const denom = f + K1 * (1 - B + (B * doc.length) / avgdl);
			score += idf * ((f * (K1 + 1)) / denom);
		}
		return { key: doc.key, score };
	});

	return scored
		.filter((s) => s.score > 0)
		.sort((a, b) => b.score - a.score)
		.map((s) => s.key);
}
