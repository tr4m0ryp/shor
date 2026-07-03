// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Parse a MITRE CAPEC STIX 2.1 bundle into seed exemplars (`known` tier).
 *
 * Pure and defensive: `parseCapecStix` takes an ALREADY-parsed bundle object
 * (the CLI reads the multi-MB `mitre/cti` file from `SHOR_CAPEC_STIX_PATH` and
 * JSON-parses it — that file is NEVER committed). It selects `attack-pattern`
 * objects and maps the CAPEC fields onto {@link SeedExemplar}:
 *   name                    -> technique
 *   description             -> rootCause
 *   x_capec_prerequisites   -> preconditions
 *   external_references:
 *     source_name "capec"   -> capecId (external_id)
 *     source_name "cwe"     -> cwe (external_id, first)
 *   x_capec_example_instances[0] -> pocSkeleton (Vector B; may be empty)
 *   x_capec_consequences    -> sink + probeSignal (flattened impact phrases)
 *
 * CAPEC is a public catalogue, so these carry `noveltyTier: 'known'`. Objects
 * without a usable name are skipped rather than throwing.
 */

import type { SeedExemplar } from "../types.js";

/** Max chars kept from a CAPEC example instance used as a PoC skeleton. */
const MAX_SKELETON = 1200;

function asRecord(value: unknown): Record<string, unknown> | null {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

function asString(value: unknown): string | null {
	return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

/** Coerce a value into a clean string array (drops non-strings / blanks). */
function asStringArray(value: unknown): string[] {
	if (!Array.isArray(value)) return [];
	const out: string[] = [];
	for (const item of value) {
		const s = asString(item);
		if (s) out.push(s);
	}
	return out;
}

interface ExternalRef {
	sourceName: string | null;
	externalId: string | null;
	url: string | null;
}

function readRefs(obj: Record<string, unknown>): ExternalRef[] {
	const raw = obj.external_references;
	if (!Array.isArray(raw)) return [];
	return raw.map((r) => {
		const rec = asRecord(r) ?? {};
		return {
			sourceName: asString(rec.source_name)?.toLowerCase() ?? null,
			externalId: asString(rec.external_id),
			url: asString(rec.url),
		};
	});
}

/** Flatten `x_capec_consequences` ({ scope: [impact, ...] }) to short phrases. */
function readConsequences(obj: Record<string, unknown>): string[] {
	const cons = asRecord(obj.x_capec_consequences);
	if (!cons) return [];
	const out: string[] = [];
	for (const [scope, impacts] of Object.entries(cons)) {
		const list = asStringArray(impacts);
		if (list.length > 0) out.push(`${scope}: ${list.join(", ")}`);
	}
	return out;
}

/** Collect the tag set: CAPEC domains + abstraction level + a `capec` marker. */
function readTags(obj: Record<string, unknown>): string[] {
	const tags = new Set<string>(["capec"]);
	for (const domain of asStringArray(obj.x_capec_domains)) {
		tags.add(domain.toLowerCase());
	}
	const abstraction = asString(obj.x_capec_abstraction);
	if (abstraction) tags.add(abstraction.toLowerCase());
	return [...tags];
}

/** Map one STIX `attack-pattern` object to a {@link SeedExemplar}, or null. */
function mapAttackPattern(obj: Record<string, unknown>): SeedExemplar | null {
	const technique = asString(obj.name);
	if (!technique) return null;

	const refs = readRefs(obj);
	const capecId =
		refs.find((r) => r.sourceName === "capec")?.externalId ?? undefined;
	const cwe = refs.find((r) => r.sourceName === "cwe")?.externalId ?? undefined;
	const canonicalUrl =
		refs.find((r) => r.sourceName === "capec")?.url ??
		"https://capec.mitre.org/";

	const prereqs = asStringArray(obj.x_capec_prerequisites);
	const consequences = readConsequences(obj);
	const example = asStringArray(obj.x_capec_example_instances)[0] ?? "";

	const exemplar: SeedExemplar = {
		technique,
		...(asStringArray(obj.aliases).length > 0
			? { aliases: asStringArray(obj.aliases) }
			: {}),
		preconditions: prereqs.join("; ") || "n/a",
		rootCause: asString(obj.description) ?? "n/a",
		source: "attacker-controlled input",
		sink: consequences[0] ?? "affected component operation",
		probeSignal:
			consequences.length > 0
				? `Observable impact — ${consequences.join("; ")}`
				: "behavioral deviation consistent with the technique",
		pocSkeleton: example.slice(0, MAX_SKELETON),
		...(cwe ? { cwe } : {}),
		...(capecId ? { capecId } : {}),
		tags: readTags(obj),
		noveltyTier: "known",
		provenance: {
			source: "MITRE CAPEC",
			url: canonicalUrl,
			...(asString(obj.modified)
				? { date: asString(obj.modified) as string }
				: {}),
		},
	};
	return exemplar;
}

/**
 * Parse a STIX 2.1 bundle object into `known`-tier seed exemplars. Accepts the
 * whole bundle (`{ type: "bundle", objects: [...] }`) or a bare `objects` array;
 * anything else yields an empty list. Deprecated/revoked patterns are skipped.
 */
export function parseCapecStix(bundle: unknown): SeedExemplar[] {
	const record = asRecord(bundle);
	const objects = Array.isArray(bundle)
		? bundle
		: Array.isArray(record?.objects)
			? record.objects
			: [];

	const out: SeedExemplar[] = [];
	for (const raw of objects) {
		const obj = asRecord(raw);
		if (!obj || obj.type !== "attack-pattern") continue;
		if (obj.revoked === true || obj.x_capec_status === "Deprecated") continue;
		const exemplar = mapAttackPattern(obj);
		if (exemplar) out.push(exemplar);
	}
	return out;
}
