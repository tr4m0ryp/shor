// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * De-slop pass — ORCHESTRATION + public surface (spec T14, F11).
 *
 * A finalize hook that COMPLEMENTS (never replaces) `applyImprovedText`: after the
 * improver overlay, any finding whose remediation is STILL the mapper's boilerplate
 * template gets a deterministic, finding-specific rewrite (`rewrite.ts`) — grounded
 * only in that finding's own evidence, never fabricated.
 *
 * DEFAULT: OFF. With `SHOR_DESLOP` unset (or `0`) `deslopFindings` is an identity
 * no-op — records returned unchanged, nothing logged — so a stock scan is byte-for-byte
 * unchanged. Opt IN with `SHOR_DESLOP=1`.
 *
 * Recall-safe: it only ever REWRITES prose on a finding already flagged as carrying
 * boilerplate; it never drops, re-scores, or reorders a finding.
 */

import type { FindingRecord } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { isBoilerplateRemediation } from "../../job/findings/remediation-guard.js";
import { rewriteRemediation } from "./rewrite.js";

export { rewriteRemediation } from "./rewrite.js";

/** True when the de-slop pass is enabled (default OFF; opt IN with `SHOR_DESLOP=1`). */
export function deslopEnabled(): boolean {
	const raw = (process.env.SHOR_DESLOP ?? "").trim().toLowerCase();
	return raw === "1" || raw === "on";
}

/** Per-pass counters, returned so the caller can log/assert the effect. */
export interface DeslopStats {
	/** Findings whose remediation was boilerplate on entry. */
	boilerplate: number;
	/** Boilerplate findings rewritten to finding-specific prose. */
	rewritten: number;
	/** Boilerplate findings left as-is (no anchor to specialize without inventing). */
	unspecifiable: number;
}

/**
 * Rewrite boilerplate remediation to finding-specific prose across `records`. Returns
 * a NEW array (inputs are not mutated) plus stats. Identity no-op when disabled.
 *
 * A rewritten record carries `remediation_deslopped=true` and clears
 * `remediation_boilerplate`; a boilerplate record with no usable anchor is left intact
 * but flagged `remediation_deslop_unspecifiable=true` (so it stays visible, never
 * silently "fixed"). Every rewrite and every decline is logged.
 */
export function deslopFindings(
	records: FindingRecord[],
	logger: ActivityLogger,
	enabled: boolean = deslopEnabled(),
): { records: FindingRecord[]; stats: DeslopStats } {
	const stats: DeslopStats = { boilerplate: 0, rewritten: 0, unspecifiable: 0 };
	if (!enabled || records.length === 0) {
		return { records, stats };
	}

	const out = records.map((rec) => {
		if (!isBoilerplateRemediation(rec.remediation)) return rec;
		stats.boilerplate += 1;

		const rewritten = rewriteRemediation(rec);
		if (rewritten) {
			stats.rewritten += 1;
			logger.info("deslop: rewrote boilerplate remediation to finding-specific text", {
				id: rec.id,
				category: rec.category,
			});
			const next: FindingRecord = { ...rec, remediation: rewritten, remediation_deslopped: true };
			delete next.remediation_boilerplate;
			return next;
		}

		stats.unspecifiable += 1;
		logger.warn("deslop: boilerplate remediation has no anchor to specialize — left as-is (not invented)", {
			id: rec.id,
			category: rec.category,
		});
		return { ...rec, remediation_deslop_unspecifiable: true };
	});

	logger.info("deslop pass complete", {
		total: records.length,
		boilerplate: stats.boilerplate,
		rewritten: stats.rewritten,
		unspecifiable: stats.unspecifiable,
	});
	return { records: out, stats };
}
