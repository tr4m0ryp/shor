// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Coverage model (T1 shared contract).
 *
 * Records which architectural tiers are actually present in the uploaded source
 * so downstream stages stop assuming "the upload is the whole app". A tier that
 * exists at runtime but has no source in the repo (`backend: "absent"` with a
 * live API responding) is an UNSEEN trust boundary — findings reasoning that
 * touches it must be tagged accordingly (gating lives in `findings/`, task 003;
 * this module only PRODUCES the manifest).
 *
 * Shape, filename, and the `isTierCovered` helper are pinned in the task rules.
 * Consumers import from here — they do not redefine the type.
 */

/** The architectural tiers the classifier reasons about. */
export type CoverageTier =
	| "frontend"
	| "backend"
	| "config"
	| "schema"
	| "tests";

/** Per-tier presence verdict. `partial` = some but plausibly incomplete signal. */
export type TierPresence = "present" | "absent" | "partial";

/** Coverage manifest emitted by pre-recon as `coverage_manifest.json` (T1). */
export interface CoverageManifest {
	tiers: Record<CoverageTier, TierPresence>;
	/** Live endpoints/behaviours with no corresponding source in the repo. */
	observedLiveOnly: string[];
	notes: string;
}

/** Canonical deliverable filename — pinned by the shared contract. */
export const COVERAGE_MANIFEST_FILENAME = "coverage_manifest.json";

/** Ordered tier list, useful for iteration and table rendering. */
export const COVERAGE_TIERS: readonly CoverageTier[] = [
	"frontend",
	"backend",
	"config",
	"schema",
	"tests",
] as const;

/**
 * True when `tier` is at least partially covered by repository source. `absent`
 * (and any unknown value) is the only "not covered" verdict. Downstream gating
 * uses this to decide whether a finding rests on seen or unseen code.
 */
export function isTierCovered(
	manifest: CoverageManifest,
	tier: CoverageTier,
): boolean {
	const presence = manifest.tiers[tier];
	return presence === "present" || presence === "partial";
}

/**
 * Coerce an arbitrary parsed value into a valid `CoverageManifest`, filling
 * missing/invalid fields with safe defaults (every tier `absent`, empty lists).
 * Used when reading a manifest the pre-recon agent may have written by hand —
 * never throws, always returns a well-formed manifest.
 */
export function normalizeManifest(value: unknown): CoverageManifest {
	const obj = (value ?? {}) as Record<string, unknown>;
	const rawTiers = (obj.tiers ?? {}) as Record<string, unknown>;

	const tiers = {} as Record<CoverageTier, TierPresence>;
	for (const tier of COVERAGE_TIERS) {
		tiers[tier] = coercePresence(rawTiers[tier]);
	}

	const observedLiveOnly = Array.isArray(obj.observedLiveOnly)
		? obj.observedLiveOnly.filter((s): s is string => typeof s === "string")
		: [];

	const notes = typeof obj.notes === "string" ? obj.notes : "";

	return { tiers, observedLiveOnly, notes };
}

function coercePresence(value: unknown): TierPresence {
	return value === "present" || value === "partial" || value === "absent"
		? value
		: "absent";
}
