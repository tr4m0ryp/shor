// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Per-category validation-lane status (T5: fail-loud on a failed validation lane).
 *
 * Each finding category has an exploitation (validation) agent — `<cat>-exploit`.
 * When that agent THROWS, the category's analysis findings were never validated:
 * they must NOT pass through as `firm`/`tentative` as if confirmed. The pipeline
 * records the per-category outcome into `validation_lane_status.json`, keyed by
 * category, so the findings gate can demote a failed lane's non-exploited
 * findings to `unverified_out_of_scope` (the same exclusion path the coverage
 * gate uses). A lane that runs to completion is `validated` (even if it exploited
 * nothing). A category with NO recorded status is treated as NOT failed — absence
 * of the file must reproduce pre-T5 behavior exactly (no regression).
 */

import fs from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { FINDING_CATEGORIES } from "./queue.js";
import type { FindingCategory } from "./types.js";

/** Deliverable recording whether each category's validation lane ran (T5). */
export const VALIDATION_LANE_STATUS_FILE = "validation_lane_status.json";

/**
 * Outcome of a category's exploitation (validation) lane:
 *   - `validated` — the exploit agent ran to completion (even if it exploited
 *     nothing; "ran and did not throw").
 *   - `failed`    — the exploit agent THREW; its analysis findings were never
 *     validated and must be demoted out of the emitted set.
 *   - `skipped`   — the lane was intentionally not run.
 */
export type LaneStatus = "validated" | "failed" | "skipped";

/** Partial map of category → lane status (only recorded lanes are present). */
export type LaneStatusMap = Partial<Record<FindingCategory, LaneStatus>>;

const LANE_STATUSES: readonly LaneStatus[] = ["validated", "failed", "skipped"];

const EXPLOIT_AGENT_SUFFIX = "-exploit";

/**
 * Map an exploit agent name to its finding category: `"<cat>-exploit"` ⇒ `<cat>`.
 * Returns `undefined` for any agent that is not a recognized exploit lane — only
 * EXPLOIT_AGENTS produce lane status, so `runGroup` can call the recorder
 * unconditionally and have vuln/synthesis agents no-op.
 */
export function categoryForExploitAgent(
	agentName: string,
): FindingCategory | undefined {
	if (!agentName.endsWith(EXPLOIT_AGENT_SUFFIX)) return undefined;
	const cat = agentName.slice(0, -EXPLOIT_AGENT_SUFFIX.length);
	return (FINDING_CATEGORIES as readonly string[]).includes(cat)
		? (cat as FindingCategory)
		: undefined;
}

/** Coerce a parsed JSON value into a well-formed lane-status map. */
function normalizeLaneStatus(parsed: unknown): LaneStatusMap {
	const out: LaneStatusMap = {};
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return out;
	for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
		if (!(FINDING_CATEGORIES as readonly string[]).includes(key)) continue;
		if (typeof value === "string" && (LANE_STATUSES as readonly string[]).includes(value)) {
			out[key as FindingCategory] = value as LaneStatus;
		}
	}
	return out;
}

/**
 * Read `validation_lane_status.json` from `deliverablesPath`, SYNCHRONOUSLY (the
 * findings gate that consumes it must stay synchronous — see gating.ts). Returns
 * an empty map when the file is absent or unparseable: a category with no
 * recorded status is treated as NOT failed (no regression vs the pre-T5 path).
 */
export function readLaneStatus(
	deliverablesPath: string,
	logger: ActivityLogger,
): LaneStatusMap {
	const file = path.join(deliverablesPath, VALIDATION_LANE_STATUS_FILE);
	try {
		if (!fs.existsSync(file)) return {};
		return normalizeLaneStatus(JSON.parse(fs.readFileSync(file, "utf8")));
	} catch (err) {
		logger.warn("Failed to read/parse validation lane status; treating all lanes as not-failed", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
		return {};
	}
}

/**
 * Record one category's lane status into `validation_lane_status.json`, merging
 * with any existing entries. SYNCHRONOUS read-modify-write so concurrent exploit
 * agents in the same process cannot lose each other's updates — Node runs this
 * block to completion before another task can interleave. Best-effort: a write
 * failure is logged and swallowed (it must never abort the pipeline).
 */
export function recordLaneStatus(
	deliverablesPath: string,
	category: FindingCategory,
	status: LaneStatus,
	logger: ActivityLogger,
): void {
	const file = path.join(deliverablesPath, VALIDATION_LANE_STATUS_FILE);
	try {
		const current = readLaneStatus(deliverablesPath, logger);
		current[category] = status;
		fs.writeFileSync(file, `${JSON.stringify(current, null, 2)}\n`);
	} catch (err) {
		logger.warn("Failed to record validation lane status; continuing", {
			file,
			category,
			status,
			error: err instanceof Error ? err.message : String(err),
		});
	}
}

/**
 * Record the outcome of an exploit agent's lane, mapping its name → category. A
 * no-op for any non-exploit agent (only EXPLOIT_AGENTS produce lane status), so
 * `runGroup` can call this for every agent it runs without branching on the name.
 */
export function recordExploitLaneOutcome(
	deliverablesPath: string,
	agentName: string,
	status: LaneStatus,
	logger: ActivityLogger,
): void {
	const category = categoryForExploitAgent(agentName);
	if (!category) return;
	recordLaneStatus(deliverablesPath, category, status, logger);
}
