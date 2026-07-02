// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Finding grader (spec T13 + T10) — STABLE seam consumed by `collectFindings`.
 *
 * Re-labels every finding by EVIDENCE QUALITY and REAL RISK: it sets confidence
 * from evidence + oracle disposition, sets reachability, recomputes severity from
 * the matched threat (impact x raised-likelihood x reachability x attacker
 * control, CAPPING low-reachability findings), and records the `threat_id` it
 * mapped to. It NEVER drops a finding — the output has exactly the input findings,
 * in order, with sharpened labels.
 *
 * SYNCHRONOUS by contract: `collectFindings` (and its callers in
 * cli-finalization.ts) are synchronous, so the live LLM scoring runs earlier as
 * the async {@link runGraderPass} and is persisted to `finding_grades.json`; this
 * pass reads those grades and, where they are absent, falls back to deterministic
 * heuristics. FAIL-OPEN end to end: a missing/malformed threat model or grade
 * file, or any per-finding error, leaves that finding's existing labels untouched.
 */

import fs from "node:fs";
import path from "node:path";
import type { FindingRecord } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import {
	parseThreatModel,
	type Threat,
	THREAT_MODEL_FILE,
} from "../threat-model/index.js";
import { calibrateFinding } from "./calibration.js";
import { readGrades } from "./grades.js";

export { defaultGradeFor, GRADES_FILE, type GradeRow } from "./grades.js";
export { gradeWriteup, type GraderPassOptions, runGraderPass } from "./llm.js";
export { buildGraderPrompt, REPORT_GRADER_RUBRIC } from "./prompt.js";
export { calibrateFinding, type FindingPatch, matchThreat } from "./calibration.js";

/** Options threaded to the grader (deliverables location + logger). */
export interface GradeOptions {
	deliverablesPath: string;
	logger: ActivityLogger;
}

/** Read + parse `threat_model.json`, or `[]` when it is absent/unparseable. */
function readThreats(deliverablesPath: string, logger: ActivityLogger): Threat[] {
	const file = path.join(deliverablesPath, THREAT_MODEL_FILE);
	try {
		if (!fs.existsSync(file)) return [];
		const model = parseThreatModel(fs.readFileSync(file, "utf8"));
		return model?.threats ?? [];
	} catch (err) {
		logger.warn("Failed to read/parse threat model; severity calibration skipped", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
		return [];
	}
}

/**
 * Grade findings: re-label each by evidence quality + real risk, in place over a
 * copy. Reads the persisted LLM grades and the threat model (both best-effort),
 * then calibrates every finding. Per-finding fail-open — any error keeps that
 * finding's existing labels — and the returned array always has the SAME findings
 * as the input (no drops).
 */
export function gradeFindings(
	findings: FindingRecord[],
	opts: GradeOptions,
): FindingRecord[] {
	const { deliverablesPath, logger } = opts;
	const threats = readThreats(deliverablesPath, logger);
	const grades = readGrades(deliverablesPath, logger);
	if (threats.length === 0 && grades.size === 0) {
		// No new grading signal on disk; only on-finding oracle dispositions can
		// still re-label. Skip the work entirely when there is nothing to do.
		const anyOracle = findings.some((f) => f.oracle_disposition !== undefined);
		if (!anyOracle) return findings;
	}

	let changed = 0;
	const graded = findings.map((finding) => {
		try {
			const patch = calibrateFinding(finding, threats, grades.get(finding.id));
			const next: FindingRecord = { ...finding, ...patch };
			if (
				next.severity !== finding.severity ||
				next.confidence !== finding.confidence ||
				next.reachability !== finding.reachability ||
				next.threat_id !== finding.threat_id
			) {
				changed += 1;
			}
			return next;
		} catch (err) {
			// FAIL OPEN: never let a single finding's calibration drop it or throw.
			logger.warn("Grader calibration failed for finding; keeping existing labels", {
				id: finding.id,
				error: err instanceof Error ? err.message : String(err),
			});
			return finding;
		}
	});

	logger.info("Graded findings", {
		total: graded.length,
		relabelled: changed,
		threats: threats.length,
		grades: grades.size,
	});
	return graded;
}
