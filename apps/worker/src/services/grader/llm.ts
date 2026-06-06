// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Async LLM grader (spec T13). Scores each finding's write-up for evidence
 * quality + reachability with a structured-output agent, then persists the
 * grades for the synchronous `gradeFindings` pass to consume.
 *
 * This is the PRODUCER seam, mirroring `runOraclePhase`: it is async (an LLM
 * call), so it runs as a post-exploitation pipeline step — NOT inside the
 * synchronous `collectFindings`, which must stay sync for its callers
 * (cli-finalization.ts) and tests. Wiring it into the pipeline is a one-line
 * `await runGraderPass(...)`; until then the sync pass falls back to heuristics.
 *
 * FAIL-OPEN throughout: `runStructured` never throws, and `parseOr` collapses any
 * grader failure to the finding's EXISTING labels ({@link defaultGradeFor}), so a
 * flaky/unavailable model can only ever leave a finding's labels untouched.
 */

import {
	type FindingGrade,
	findingGradeSchema,
	parseOr,
	runStructured,
} from "../../ai/structured/index.js";
import type { FindingRecord } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { defaultGradeFor, type GradeRow, writeGrades } from "./grades.js";
import { buildGraderPrompt } from "./prompt.js";

/** Options threaded to the async grader (deliverables location + logger). */
export interface GraderPassOptions {
	deliverablesPath: string;
	logger: ActivityLogger;
}

/**
 * Grade ONE finding's write-up with the LLM. Never throws; on any failure the
 * structured result is `ok:false` and `parseOr` returns {@link defaultGradeFor}
 * — the finding's existing labels — so grading can only sharpen, never erase.
 */
export async function gradeWriteup(
	finding: FindingRecord,
	opts: GraderPassOptions,
): Promise<FindingGrade> {
	const result = await runStructured<FindingGrade>({
		prompt: buildGraderPrompt(finding),
		sourceDir: opts.deliverablesPath,
		schema: findingGradeSchema,
		agentName: "report-grader",
		logger: opts.logger,
	});
	return parseOr(result, defaultGradeFor(finding));
}

/**
 * Grade EVERY finding and persist the rows to `finding_grades.json`. Sequential
 * by design — grading is a cheap structured call and serial keeps the model load
 * predictable. Best-effort and side-effecting only: it writes the deliverable and
 * returns the rows; it never mutates the findings (the sync pass applies them).
 */
export async function runGraderPass(
	findings: FindingRecord[],
	opts: GraderPassOptions,
): Promise<GradeRow[]> {
	const rows: GradeRow[] = [];
	for (const finding of findings) {
		const grade = await gradeWriteup(finding, opts);
		rows.push({ id: finding.id, ...grade });
	}
	if (rows.length > 0) await writeGrades(opts.deliverablesPath, rows, opts.logger);
	opts.logger.info("Graded finding write-ups", { count: rows.length });
	return rows;
}
