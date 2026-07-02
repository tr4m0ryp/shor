// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Renderers for the OPTIONAL sibling artifacts the scan context assembler folds
 * in alongside the threat model:
 *   - `historical_signal.json` (task 006) -> {{HISTORICAL_SEED}}
 *   - `scan_identities.json`    (task 008) -> {{IDENTITIES}}
 *
 * Both are LLM/harness-authored and their exact shapes belong to their producing
 * tasks, so these readers are permissive about structure but STRICT about what
 * they emit. In particular the identity renderer is allowlist-driven: it reads
 * ONLY label/role fields and can never surface a credential (ADR-050).
 */

import { asRecord, firstString, truncate } from "./util.js";

const MAX_HOTSPOTS = 10;
const MAX_IDENTITIES = 20;

/** Identity fields safe to surface — labels and roles ONLY, never secrets. */
const IDENTITY_LABEL_KEYS = ["label", "name", "title"] as const;
const IDENTITY_ROLE_KEYS = ["role", "privilege", "level"] as const;

function renderHotspot(value: unknown): string {
	if (typeof value === "string") return `- ${truncate(value, 160)}`;
	const o = asRecord(value);
	if (o === null) return "";
	const where =
		firstString(o, ["area", "location", "path", "endpoint", "component", "file"]) ??
		"(area)";
	const why = firstString(o, ["reason", "note", "why", "summary", "description"]);
	return `- ${truncate(where, 100)}${why ? `: ${truncate(why, 140)}` : ""}`;
}

/**
 * Render the historical-signal artifact into a {{HISTORICAL_SEED}} string.
 * Prefers an explicit `summary`; otherwise lists the top hot-spots (accepts a
 * bare array or `{ hotspots: [...] }`). Returns `null` when nothing usable is
 * present so the assembler leaves the field unset (-> "(none)").
 */
export function renderHistoricalSeed(raw: unknown): string | null {
	const obj = asRecord(raw);
	if (obj !== null) {
		const summary = firstString(obj, ["summary", "text", "render"]);
		if (summary) return summary;
	}
	const hotspots = Array.isArray(raw)
		? raw
		: obj !== null && Array.isArray(obj.hotspots)
			? obj.hotspots
			: null;
	if (hotspots && hotspots.length > 0) {
		const lines = hotspots
			.slice(0, MAX_HOTSPOTS)
			.map(renderHotspot)
			.filter((l) => l.length > 0);
		if (lines.length > 0) return lines.join("\n");
	}
	return null;
}

function renderIdentity(value: unknown): string {
	if (typeof value === "string") return `- ${truncate(value, 80)}`;
	const o = asRecord(value);
	if (o === null) return "";
	const label = firstString(o, IDENTITY_LABEL_KEYS) ?? "identity";
	let role = firstString(o, IDENTITY_ROLE_KEYS);
	if (role === undefined && Array.isArray(o.roles)) {
		const roles = o.roles.filter((r): r is string => typeof r === "string");
		if (roles.length > 0) role = roles.join("/");
	}
	return `- ${truncate(label, 60)}${role ? ` (role: ${truncate(role, 60)})` : ""}`;
}

/**
 * Render the identity artifact into an {{IDENTITIES}} string — METADATA ONLY.
 * Accepts a bare array or `{ identities: [...] }`. By construction this reads
 * ONLY allowlisted label/role keys, so password/token/cookie/secret fields in
 * the source object are never emitted. Returns `null` when empty.
 */
export function renderIdentities(raw: unknown): string | null {
	const obj = asRecord(raw);
	const list = Array.isArray(raw)
		? raw
		: obj !== null && Array.isArray(obj.identities)
			? obj.identities
			: null;
	if (!list || list.length === 0) return null;
	const lines = list
		.slice(0, MAX_IDENTITIES)
		.map(renderIdentity)
		.filter((l) => l.length > 0);
	return lines.length > 0 ? lines.join("\n") : null;
}
