// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// Threat-model schema adapted from the Apache-2.0 licensed threat-model harness
// schema (https://www.apache.org/licenses/LICENSE-2.0).

/**
 * Machine-readable threat model emitted by the threat-model agent as
 * `threat_model.json`. The renderer ({@link ./render}) turns it into the
 * compact `{{THREAT_MODEL}}` prompt summary; downstream severity (task 015)
 * maps a finding to a {@link Threat} by its stable `id`.
 */

import {
	asRecord,
	asString,
	asStringArray,
	coerceEnum,
} from "./util.js";

/** Asset sensitivity, ordered low -> critical. */
export const SENSITIVITY_LEVELS = ["low", "medium", "high", "critical"] as const;
export type SensitivityLevel = (typeof SENSITIVITY_LEVELS)[number];

/** Threat impact, ordered low -> existential. */
export const IMPACT_LEVELS = [
	"low",
	"medium",
	"high",
	"critical",
	"existential",
] as const;
export type ImpactLevel = (typeof IMPACT_LEVELS)[number];

/** Threat likelihood, ordered very_rare -> almost_certain. Evidence raises it. */
export const LIKELIHOOD_LEVELS = [
	"very_rare",
	"rare",
	"unlikely",
	"possible",
	"likely",
	"very_likely",
	"almost_certain",
] as const;
export type LikelihoodLevel = (typeof LIKELIHOOD_LEVELS)[number];

/** Attacker position / origin for a threat. */
export const THREAT_ACTORS = [
	"remote_unauth",
	"remote_auth",
	"adjacent_network",
	"local_user",
	"local_admin",
	"supply_chain",
	"insider",
] as const;
export type ThreatActor = (typeof THREAT_ACTORS)[number];

/** A thing worth protecting; `sensitivity` drives crown-jewel ranking. */
export interface Asset {
	asset: string;
	description: string;
	sensitivity: SensitivityLevel;
}

/** Where untrusted input enters and which assets become reachable past it. */
export interface EntryPoint {
	entry_point: string;
	trust_boundary: string;
	reachable_assets: string[];
}

/**
 * One threat, written "at the abstraction level where it survives a patch" — a
 * structural abuse case rather than a single bug. `id` (T1, T2, ...) is the
 * stable handle downstream findings reference.
 */
export interface Threat {
	id: string;
	threat: string;
	actor: ThreatActor;
	surface: string;
	asset: string;
	impact: ImpactLevel;
	likelihood: LikelihoodLevel;
	status: string;
	controls: string;
	evidence: string;
}

/** A candidate the model considered and intentionally set aside, with reason. */
export interface Deprioritized {
	item: string;
	reason: string;
}

/** Where the model came from, for auditability. */
export interface Provenance {
	sources: string[];
	notes: string;
}

/** Full parsed threat model. */
export interface ThreatModel {
	system_context: string;
	assets: Asset[];
	entry_points: EntryPoint[];
	threats: Threat[];
	deprioritized: Deprioritized[];
	provenance: Provenance;
}

/** 1-based rank of an impact level (low=1 .. existential=5). */
export function impactOrdinal(level: ImpactLevel): number {
	return IMPACT_LEVELS.indexOf(level) + 1;
}

/** 1-based rank of a likelihood level (very_rare=1 .. almost_certain=7). */
export function likelihoodOrdinal(level: LikelihoodLevel): number {
	return LIKELIHOOD_LEVELS.indexOf(level) + 1;
}

/** 1-based rank of a sensitivity level (low=1 .. critical=4). */
export function sensitivityOrdinal(level: SensitivityLevel): number {
	return SENSITIVITY_LEVELS.indexOf(level) + 1;
}

/** Priority score = impact x likelihood. Higher means hunt this first. */
export function threatScore(threat: Threat): number {
	return impactOrdinal(threat.impact) * likelihoodOrdinal(threat.likelihood);
}

function normalizeAsset(value: unknown): Asset {
	const o = asRecord(value) ?? {};
	return {
		asset: asString(o.asset),
		description: asString(o.description),
		sensitivity: coerceEnum(o.sensitivity, SENSITIVITY_LEVELS, "low"),
	};
}

function normalizeEntryPoint(value: unknown): EntryPoint {
	const o = asRecord(value) ?? {};
	return {
		entry_point: asString(o.entry_point),
		trust_boundary: asString(o.trust_boundary),
		reachable_assets: asStringArray(o.reachable_assets),
	};
}

function normalizeThreat(value: unknown, index: number): Threat {
	const o = asRecord(value) ?? {};
	return {
		id: asString(o.id) || `T${index + 1}`,
		threat: asString(o.threat),
		actor: coerceEnum(o.actor, THREAT_ACTORS, "remote_unauth"),
		surface: asString(o.surface),
		asset: asString(o.asset),
		impact: coerceEnum(o.impact, IMPACT_LEVELS, "low"),
		likelihood: coerceEnum(o.likelihood, LIKELIHOOD_LEVELS, "very_rare"),
		status: asString(o.status),
		controls: asString(o.controls),
		evidence: asString(o.evidence),
	};
}

function normalizeDeprioritized(value: unknown): Deprioritized {
	if (typeof value === "string") return { item: value.trim(), reason: "" };
	const o = asRecord(value) ?? {};
	return { item: asString(o.item), reason: asString(o.reason) };
}

function normalizeProvenance(value: unknown): Provenance {
	const o = asRecord(value) ?? {};
	return { sources: asStringArray(o.sources), notes: asString(o.notes) };
}

/**
 * Parse + normalize a threat model from raw JSON text or an already-parsed
 * value. Tolerant by design (LLM-authored input): unknown enum values fall back
 * to the lowest rank, missing arrays become empty, missing threat ids are
 * synthesized as `T<n>`. Returns `null` only when the input is not a JSON object
 * or has no `threats` array — the two invariants the validator relies on.
 */
export function parseThreatModel(input: unknown): ThreatModel | null {
	let raw: unknown = input;
	if (typeof input === "string") {
		try {
			raw = JSON.parse(input);
		} catch {
			return null;
		}
	}
	const obj = asRecord(raw);
	if (obj === null) return null;
	if (!Array.isArray(obj.threats)) return null;
	return {
		system_context: asString(obj.system_context),
		assets: Array.isArray(obj.assets) ? obj.assets.map(normalizeAsset) : [],
		entry_points: Array.isArray(obj.entry_points)
			? obj.entry_points.map(normalizeEntryPoint)
			: [],
		threats: obj.threats.map(normalizeThreat),
		deprioritized: Array.isArray(obj.deprioritized)
			? obj.deprioritized.map(normalizeDeprioritized)
			: [],
		provenance: normalizeProvenance(obj.provenance),
	};
}
