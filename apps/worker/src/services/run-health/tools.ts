// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Tool-breadth summary: read a category's `{category}_vuln_coverage.json` (the
 * deterministic post-validator's output) and decide whether ANY expected tool
 * left a trace. The run analysis found categories that ran no tools at all and
 * produced findings by code-reading alone — this surfaces that as a loud signal
 * rather than something you discover by hand-pulling artifacts. Pure — no I/O.
 */

export interface CategoryToolHealth {
	category: string;
	/** The read-only floor tool (semgrep) left a trace. */
	floorMet: boolean;
	/** Recommended category tools that left a trace. */
	recommendedRun: string[];
	/** True when the floor OR any recommended tool ran — i.e. some tool evidence. */
	toolEvidence: boolean;
}

/** Summarize one category's coverage JSON (unknown-shaped, defensively read). */
export function summarizeCategoryTools(
	category: string,
	coverage: unknown,
): CategoryToolHealth {
	const record =
		coverage !== null && typeof coverage === "object"
			? (coverage as Record<string, unknown>)
			: {};
	const floorMet = record.floorMet === true;
	const recommendedRun = Array.isArray(record.recommendedRun)
		? record.recommendedRun.filter((x): x is string => typeof x === "string")
		: [];
	return {
		category,
		floorMet,
		recommendedRun,
		toolEvidence: floorMet || recommendedRun.length > 0,
	};
}
