// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

//
// Evidence-grading rubric adapted from the Apache-2.0 licensed report-grader
// harness (https://www.apache.org/licenses/LICENSE-2.0).

/**
 * Grader prompt (spec T13). Asks the LLM to score the EVIDENCE QUALITY of one
 * finding write-up — not whether the bug sounds plausible, but whether the prose
 * PROVES it with concrete, reproducible grounding — and to judge reachability.
 * The structured reply is validated against {@link findingGradeSchema}; the
 * caller ({@link ../calibration}) recomputes the authoritative severity and
 * confidence from the threat model, so `severity`/`confidence` here are advisory.
 */

import type { FindingRecord } from "../../job/findings/types.js";

/** Collapse whitespace and clip to `max` chars so a write-up can't blow the prompt. */
function clip(value: unknown, max: number): string {
	const t = String(value ?? "").replace(/\s+/g, " ").trim();
	return t.length <= max ? t : `${t.slice(0, Math.max(0, max - 3))}...`;
}

/**
 * The standing rubric. Evidence is scored 0/1/2 demanding concrete grounding
 * (a replayable request/response, an observed signal, a precise file:line);
 * absence of evidence forces a LOW score. Reachability captures whether
 * untrusted external input can actually reach the vulnerable code.
 */
export const REPORT_GRADER_RUBRIC = [
	"You are a security finding GRADER. Score the EVIDENCE QUALITY of ONE",
	"vulnerability write-up. Grade ONLY what the write-up demonstrates — not how",
	"plausible the bug sounds. Absence of evidence is itself a LOW score.",
	"",
	"evidence_score (integer 0, 1, or 2):",
	"  2 STRONG  — a concrete reproduction (an actual request AND the observed",
	"              response/signal), or an oracle-confirmed live exploit, anchored",
	"              to a specific file:line. A reader could replay it as written.",
	"  1 MODERATE— real grounding (a precise file:line sink with a tainted-input",
	"              path, or a described observed signal) but NO end-to-end repro.",
	"  0 THIN    — assertion only: no request/response, no observed signal, no",
	"              concrete file:line. Speculative or boilerplate prose.",
	"",
	"reachability — can untrusted, EXTERNAL input reach the vulnerable code?",
	"  REACHABLE    — reachable from an external / untrusted entry point.",
	"  HARNESS_ONLY — only via a test / harness / fixture, not live traffic.",
	"  UNCLEAR      — the write-up does not establish reachability.",
	"",
	"Also echo your best severity (critical|high|medium|low|info) and confidence",
	"(confirmed|firm|tentative) as ADVISORY fields; the caller recomputes the",
	"authoritative values from the threat model. Return ONLY the schema object.",
].join("\n");

/** Build the per-finding grader prompt: the rubric followed by the write-up under grade. */
export function buildGraderPrompt(finding: FindingRecord): string {
	const loc = finding.vulnerable_code_location;
	const locStr = loc?.file ? `${loc.file}:${loc.line ?? "?"}` : "(none)";
	const repro = Array.isArray(finding.repro_steps)
		? finding.repro_steps.map((s) => clip(s, 200)).join(" | ")
		: "";
	const lines = [
		REPORT_GRADER_RUBRIC,
		"",
		"=== WRITE-UP UNDER GRADE ===",
		`id: ${clip(finding.id, 80)}`,
		`title: ${clip(finding.title, 160)}`,
		`category: ${clip(finding.category, 40)}  cwe: ${clip(finding.cwe, 40)}`,
		`vulnerable_code_location: ${clip(locStr, 200)}`,
		`current_confidence: ${clip(finding.confidence, 20)}`,
		finding.oracle_disposition
			? `oracle_disposition: ${clip(finding.oracle_disposition, 20)}`
			: "oracle_disposition: (none)",
		`evidence: ${clip(finding.evidence, 1200)}`,
		`safe_poc: ${clip(finding.safe_poc, 800)}`,
		`repro_steps: ${clip(repro, 800)}`,
	];
	return lines.join("\n");
}
