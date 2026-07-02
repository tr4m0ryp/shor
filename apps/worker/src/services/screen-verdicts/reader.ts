// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Deliverable readers for the screen-verdict step.
 *
 * Two artifacts feed the router:
 *   - NEW: `{category}_screen_verdicts.json` — the N-vote panel output
 *     (`ScreenVerdictEntry[]`, the stable contract from `services/screen-panel`).
 *   - LEGACY: `{category}_screen_rejected.json` — the pre-panel adversarial-screen
 *     audit file (`[{ id, screen_reason }]`), kept as a backward-compat fallback.
 *
 * Both readers are best-effort: a missing file returns `undefined` (silently —
 * absence is normal), and a malformed/unparseable file is logged and ALSO mapped
 * to `undefined` so the caller treats it as "panel did not run" and may fall back
 * to the legacy file rather than silently dropping its refutations.
 */

import fs from "node:fs";
import path from "node:path";
import type { FindingCategory } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type {
	ScreenDecision,
	ScreenVerdictEntry,
	ScreenVote,
} from "../screen-panel/types.js";

const SCREEN_VERDICTS_SUFFIX = "_screen_verdicts.json";
const SCREEN_REJECTED_SUFFIX = "_screen_rejected.json";

const SCREEN_DECISIONS: ReadonlySet<string> = new Set<ScreenDecision>([
	"refute",
	"support",
	"uncertain",
]);

/**
 * Parse a deliverable as a JSON array. Returns `undefined` for an absent file
 * (no log — absence is the common case) and for a malformed / non-array file
 * (logged once). Never throws.
 */
function readJsonArray(
	file: string,
	logger: ActivityLogger,
): unknown[] | undefined {
	try {
		if (!fs.existsSync(file)) return undefined;
		const parsed: unknown = JSON.parse(fs.readFileSync(file, "utf8"));
		if (!Array.isArray(parsed)) {
			logger.warn("Screen file is not a JSON array; skipping", { file });
			return undefined;
		}
		return parsed;
	} catch (err) {
		logger.warn("Failed to read/parse screen file; skipping", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
		return undefined;
	}
}

/** Coerce one raw ballot into a `ScreenVote`, dropping ones with no valid verdict. */
function normalizeVotes(raw: unknown): ScreenVote[] {
	if (!Array.isArray(raw)) return [];
	const votes: ScreenVote[] = [];
	for (const item of raw) {
		if (!item || typeof item !== "object") continue;
		const rec = item as Record<string, unknown>;
		const verdict = rec.verdict;
		if (typeof verdict !== "string" || !SCREEN_DECISIONS.has(verdict)) continue;
		votes.push({
			voter: typeof rec.voter === "number" ? rec.voter : 0,
			lens: typeof rec.lens === "string" ? rec.lens : "",
			verdict: verdict as ScreenDecision,
			reason: typeof rec.reason === "string" ? rec.reason : "",
		});
	}
	return votes;
}

/** Coerce one raw element into a `ScreenVerdictEntry`, or drop it if unusable. */
function normalizeEntry(raw: unknown): ScreenVerdictEntry | undefined {
	if (!raw || typeof raw !== "object") return undefined;
	const rec = raw as Record<string, unknown>;
	const id = typeof rec.id === "string" ? rec.id.trim() : "";
	if (!id) return undefined;
	const decision = rec.decision;
	if (typeof decision !== "string" || !SCREEN_DECISIONS.has(decision)) {
		return undefined;
	}
	return {
		id,
		votes: normalizeVotes(rec.votes),
		decision: decision as ScreenDecision,
	};
}

/**
 * Read the panel verdicts for one category.
 *
 * Returns the normalized entries (possibly empty — a panel that refuted nothing)
 * when the file is a valid JSON array, signaling "the panel ran". Returns
 * `undefined` when the file is absent OR malformed, signaling "no usable panel
 * output" so the caller may fall back to the legacy file.
 */
export function readScreenVerdicts(
	deliverablesPath: string,
	category: FindingCategory,
	logger: ActivityLogger,
): ScreenVerdictEntry[] | undefined {
	const file = path.join(
		deliverablesPath,
		`${category}${SCREEN_VERDICTS_SUFFIX}`,
	);
	const raw = readJsonArray(file, logger);
	if (raw === undefined) return undefined;
	const entries: ScreenVerdictEntry[] = [];
	for (const item of raw) {
		const entry = normalizeEntry(item);
		if (entry) entries.push(entry);
	}
	return entries;
}

/**
 * Read the legacy `{category}_screen_rejected.json` audit file into an
 * `id → screen_reason` map. Returns `undefined` when absent or malformed (the
 * caller then leaves the category untouched). Best-effort: empty / id-less
 * entries are skipped.
 */
export function readLegacyRejections(
	deliverablesPath: string,
	category: FindingCategory,
	logger: ActivityLogger,
): Map<string, string> | undefined {
	const file = path.join(
		deliverablesPath,
		`${category}${SCREEN_REJECTED_SUFFIX}`,
	);
	const raw = readJsonArray(file, logger);
	if (raw === undefined) return undefined;
	const byId = new Map<string, string>();
	for (const item of raw) {
		if (!item || typeof item !== "object") continue;
		const rec = item as Record<string, unknown>;
		const id = typeof rec.id === "string" ? rec.id.trim() : "";
		if (!id) continue;
		byId.set(id, typeof rec.screen_reason === "string" ? rec.screen_reason : "");
	}
	return byId;
}
