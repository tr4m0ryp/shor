// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Run-health observability — derive and loudly surface the two silent
 * underperformance signals (screen fail-open rate, vuln tool breadth) so a bad
 * scan announces itself.
 */

export {
	type CategoryScreenHealth,
	classifyVote,
	summarizeCategoryScreen,
	type VoteClass,
} from "./screen.js";
export {
	buildAlerts,
	emitRunHealth,
	type RunHealthReport,
} from "./summary.js";
export {
	type CategoryToolHealth,
	summarizeCategoryTools,
} from "./tools.js";
