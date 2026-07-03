// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Verbalize a seed exemplar into the retrieval representation.
 *
 * Mirrors task 011's finding verbalizer (`../schema/verbalize.ts`): a labeled
 * Vul-RAG doc (Vector A) with a contextual metadata prefix, plus the PoC
 * skeleton as the code-vector text (Vector B). Pure and total — every exemplar
 * yields all labels, absent optionals render as `n/a`. No scrub is performed:
 * seeds are public research (no secrets/PII), unlike client findings.
 */

import type { SeedExemplar, VerbalizedSeed } from "./types.js";

/** Labels in the fixed order the verbalized seed doc renders them. */
export const SEED_DOC_LABELS = [
	"TECHNIQUE",
	"PRECONDITIONS",
	"ROOT CAUSE",
	"DATA FLOW",
	"PROBE SIGNAL",
	"POC SKELETON",
	"CWE+CAPEC",
] as const;

const NA = "n/a";

/** Trim a value to a non-empty string, else `n/a`. */
function orNa(value: string | undefined | null): string {
	const v = value?.trim();
	return v ? v : NA;
}

/** The TECHNIQUE line — name plus any aliases in parentheses. */
function techniqueLine(seed: SeedExemplar): string {
	const aliases = (seed.aliases ?? []).map((a) => a.trim()).filter(Boolean);
	return aliases.length > 0
		? `${seed.technique} (aka ${aliases.join(", ")})`
		: seed.technique;
}

/** "<source> -> <sink>" with `n/a` placeholders. */
function dataFlowLine(seed: SeedExemplar): string {
	return `${orNa(seed.source)} -> ${orNa(seed.sink)}`;
}

/** "CWE-x / CAPEC-y" with `n/a` placeholders. */
function cweCapecLine(seed: SeedExemplar): string {
	return `${orNa(seed.cwe)} / ${orNa(seed.capecId)}`;
}

/**
 * Contextual-retrieval metadata prefix (mirrors task 011 / R3): one compact line
 * of the highest-signal filters, prepended before embedding.
 */
export function seedMetadataPrefix(seed: SeedExemplar): string {
	const tags = seed.tags.length > 0 ? seed.tags.join(",") : NA;
	const parts = [
		`CWE=${orNa(seed.cwe)}`,
		`CAPEC=${orNa(seed.capecId)}`,
		`tier=${seed.noveltyTier}`,
		`tags=${tags}`,
	];
	return `[${parts.join(" | ")}]`;
}

/** Assemble the labeled doc body (without the metadata prefix). */
function renderSeedDoc(seed: SeedExemplar): string {
	const values: Record<(typeof SEED_DOC_LABELS)[number], string> = {
		TECHNIQUE: techniqueLine(seed),
		PRECONDITIONS: orNa(seed.preconditions),
		"ROOT CAUSE": orNa(seed.rootCause),
		"DATA FLOW": dataFlowLine(seed),
		"PROBE SIGNAL": orNa(seed.probeSignal),
		"POC SKELETON": orNa(seed.pocSkeleton),
		"CWE+CAPEC": cweCapecLine(seed),
	};
	return SEED_DOC_LABELS.map((label) => `${label}: ${values[label]}`).join(
		"\n",
	);
}

/**
 * Render a seed exemplar into its full verbalized representation. Pure and
 * total. `codeText` is the raw PoC skeleton (Vector B); an exemplar with no
 * skeleton yields an empty `codeText`, and the caller then writes no code vector.
 */
export function verbalizeSeed(seed: SeedExemplar): VerbalizedSeed {
	const metadataPrefix = seedMetadataPrefix(seed);
	const doc = renderSeedDoc(seed);
	return {
		metadataPrefix,
		doc,
		text: `${metadataPrefix}\n\n${doc}`,
		codeText: seed.pocSkeleton?.trim() ?? "",
	};
}
