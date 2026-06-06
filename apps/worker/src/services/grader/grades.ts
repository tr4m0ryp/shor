// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Grade store — the `finding_grades.json` deliverable that bridges the ASYNC LLM
 * grader to the SYNC `gradeFindings` pass.
 *
 * The async producer ({@link ../llm}.runGraderPass) scores each write-up with the
 * LLM and persists the grades here; the synchronous consumer
 * ({@link ./index}.gradeFindings, which runs inside `collectFindings` and so must
 * not be async) reads them back. This mirrors how `applyScreenVerdicts` reads the
 * screen agents' `{category}_screen_rejected.json` audit files. Every read is
 * best-effort: a missing or malformed file simply yields no grades, and the sync
 * calibration falls back to deterministic heuristics — it never throws.
 */

import fs from "node:fs";
import path from "node:path";
import { promises as fsp } from "node:fs";
import type { FindingGrade } from "../../ai/structured/index.js";
import type { FindingRecord } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";

/** Deliverable filename holding the LLM evidence grades, keyed by finding id. */
export const GRADES_FILE = "finding_grades.json";

/** One persisted grade row: a {@link FindingGrade} tagged with its finding id. */
export type GradeRow = FindingGrade & { id: string };

/**
 * Map a finding's CURRENT labels onto a {@link FindingGrade}. Used as the
 * fail-open fallback for `parseOr` (grader failed -> keep existing labels) and as
 * the deterministic grade when no LLM grade is on disk.
 */
export function defaultGradeFor(finding: FindingRecord): FindingGrade {
	const score: 0 | 1 | 2 =
		finding.confidence === "confirmed" ? 2 : finding.confidence === "firm" ? 1 : 0;
	return {
		evidence_score: score,
		severity: finding.severity,
		reachability: finding.reachability ?? "UNCLEAR",
		confidence: finding.confidence,
	};
}

/** Coerce one parsed row into a {@link GradeRow}, or `null` if it has no usable id. */
function normalizeRow(value: unknown): GradeRow | null {
	if (!value || typeof value !== "object") return null;
	const o = value as Record<string, unknown>;
	const id = typeof o.id === "string" ? o.id.trim() : "";
	if (!id) return null;
	const raw = o.evidence_score;
	const score: 0 | 1 | 2 = raw === 2 ? 2 : raw === 1 ? 1 : 0;
	return {
		id,
		evidence_score: score,
		severity: typeof o.severity === "string" ? o.severity : "",
		reachability: typeof o.reachability === "string" ? o.reachability : "UNCLEAR",
		confidence: typeof o.confidence === "string" ? o.confidence : "",
		...(typeof o.novelty === "string" ? { novelty: o.novelty } : {}),
	};
}

/**
 * Read the grades deliverable into an `id -> FindingGrade` map. SYNCHRONOUS on
 * purpose: its only caller runs inside the synchronous `collectFindings`.
 * Best-effort — a missing/unparseable file yields an empty map.
 */
export function readGrades(
	deliverablesPath: string,
	logger: ActivityLogger,
): Map<string, FindingGrade> {
	const out = new Map<string, FindingGrade>();
	const file = path.join(deliverablesPath, GRADES_FILE);
	try {
		if (!fs.existsSync(file)) return out;
		const parsed: unknown = JSON.parse(fs.readFileSync(file, "utf8"));
		const rows = Array.isArray(parsed)
			? parsed
			: Array.isArray((parsed as { grades?: unknown })?.grades)
				? (parsed as { grades: unknown[] }).grades
				: [];
		for (const row of rows) {
			const norm = normalizeRow(row);
			if (norm) {
				const { id, ...grade } = norm;
				out.set(id, grade);
			}
		}
	} catch (err) {
		logger.warn("Failed to read/parse finding grades; grading falls back to heuristics", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
	}
	return out;
}

/** Persist the grade rows to the deliverable (async; called by the LLM pass). */
export async function writeGrades(
	deliverablesPath: string,
	rows: GradeRow[],
	logger: ActivityLogger,
): Promise<void> {
	const file = path.join(deliverablesPath, GRADES_FILE);
	try {
		await fsp.writeFile(file, `${JSON.stringify({ grades: rows }, null, 2)}\n`);
	} catch (err) {
		logger.warn("Failed to write finding grades; sync grader will use heuristics", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
	}
}
