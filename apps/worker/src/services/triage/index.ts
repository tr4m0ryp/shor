// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Triage pre-gate — ORCHESTRATION + public surface (spec T14).
 *
 * Runs the pure deciders (`gate.ts`) over a {@link TriageInput}, LOGS every skip with
 * its reason (the gate never hard-drops a category silently), and returns the verdicts
 * plus the cleared-to-scan category set.
 *
 * DEFAULT: OFF. With `SHOR_TRIAGE_GATE` unset (or `0`) `runTriage` is an identity
 * no-op — no logging, every category cleared to scan — so a stock scan is byte-for-byte
 * unchanged. Opt IN with `SHOR_TRIAGE_GATE=1` (skip) or `=observe` (compute + log only).
 */

import type { FindingCategory } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { gateCategory, gateTarget, triageConfigFromEnv } from "./gate.js";
import type { TriageConfig, TriageInput, TriageResult, TriageVerdict } from "./types.js";

export type {
	CategorySignal,
	TargetSignal,
	TriageConfig,
	TriageDecision,
	TriageInput,
	TriageKind,
	TriageResult,
	TriageVerdict,
} from "./types.js";
export {
	deriveCategorySignals,
	DEFAULT_TRIAGE_CONFIG,
	gateCategory,
	gateTarget,
	triageConfigFromEnv,
} from "./gate.js";

/** True when the triage gate is enabled via env (mirrors the other `SHOR_*` flags). */
export function triageEnabled(): boolean {
	return triageConfigFromEnv().enabled;
}

/** Log one verdict: skips at WARN (visible in run logs), scans at INFO. */
function logVerdict(logger: ActivityLogger, v: TriageVerdict): void {
	const attrs = { kind: v.kind, subject: v.subject, reason: v.reason, wouldSkip: v.wouldSkip };
	if (v.decision === "skip") {
		logger.warn("triage: skipping subject (no cheap signal it is live)", attrs);
	} else if (v.wouldSkip) {
		logger.warn("triage(observe-only): would skip subject but scanning anyway", attrs);
	} else {
		logger.info("triage: scanning subject", attrs);
	}
}

/**
 * Run the triage gate over a target + its categories. Returns the verdicts, the
 * skipped subset, and the categories cleared to scan. When the gate is disabled the
 * result is IDENTITY: no verdicts, no skips, every input category cleared, nothing
 * logged — the stock path.
 *
 * `cfg` defaults to the env-derived config; pass an explicit config in tests.
 */
export function runTriage(
	input: TriageInput,
	logger: ActivityLogger,
	cfg: TriageConfig = triageConfigFromEnv(),
): TriageResult {
	const inputCategories = (input.categories ?? []).map((c) => c.category);
	if (!cfg.enabled) {
		return { verdicts: [], skipped: [], scanCategories: inputCategories };
	}

	const verdicts: TriageVerdict[] = [];
	if (input.target) verdicts.push(gateTarget(input.target, cfg));
	for (const signal of input.categories ?? []) verdicts.push(gateCategory(signal, cfg));

	for (const v of verdicts) logVerdict(logger, v);

	const skipped = verdicts.filter((v) => v.decision === "skip");
	const skippedCats = new Set(
		skipped.filter((v) => v.kind === "category").map((v) => v.subject),
	);
	const scanCategories = inputCategories.filter(
		(c): c is FindingCategory => !skippedCats.has(c),
	);

	// A target skip is a whole-scan decision the caller must honor explicitly; surface
	// it once more so it is never buried among per-category lines.
	const targetSkipped = skipped.some((v) => v.kind === "target");
	if (targetSkipped) {
		logger.warn("triage: TARGET flagged unreachable — caller should confirm before dropping the scan", {
			target: input.target?.target,
		});
	}

	return { verdicts, skipped, scanCategories };
}
