// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Small, defensive coercion helpers shared by the threat-model parser, renderer,
 * and artifact readers. Every threat-model / signal / identity artifact is
 * authored by an LLM agent, so the inputs are `unknown`: these helpers narrow
 * them without throwing, returning safe fallbacks on any shape mismatch.
 */

/** Narrow to a plain object (not null, not an array), else `null`. */
export function asRecord(value: unknown): Record<string, unknown> | null {
	return value !== null && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

/** Coerce to a trimmed string, or `fallback` (default "") for non-strings. */
export function asString(value: unknown, fallback = ""): string {
	return typeof value === "string" ? value.trim() : fallback;
}

/** Keep only the string members of an array; anything else yields []. */
export function asStringArray(value: unknown): string[] {
	return Array.isArray(value)
		? value.filter((x): x is string => typeof x === "string").map((x) => x.trim())
		: [];
}

/**
 * Narrow `value` to one of `allowed`; otherwise return `fallback`. Used to map an
 * LLM-authored enum-ish field onto a closed set without trusting the input.
 */
export function coerceEnum<T extends string>(
	value: unknown,
	allowed: readonly T[],
	fallback: T,
): T {
	return typeof value === "string" && (allowed as readonly string[]).includes(value)
		? (value as T)
		: fallback;
}

/**
 * Return the first non-empty string value among `keys` of `obj`. Intentionally
 * allowlist-driven: callers pass ONLY the keys they want surfaced, so a value
 * under any other key (e.g. a credential field) is never read.
 */
export function firstString(
	obj: Record<string, unknown>,
	keys: readonly string[],
): string | undefined {
	for (const key of keys) {
		const v = obj[key];
		if (typeof v === "string" && v.trim().length > 0) return v.trim();
	}
	return undefined;
}

/** Collapse whitespace and clip to `max` chars (ASCII ellipsis when clipped). */
export function truncate(value: string, max: number): string {
	const t = value.replace(/\s+/g, " ").trim();
	if (t.length <= max) return t;
	return `${t.slice(0, Math.max(0, max - 3))}...`;
}
