// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * services/taint/guard-dominance — is a sensitive sink actually behind an
 * authorization check on EVERY path (spec T10, F9b)?
 *
 * A real CFG-dominator query on task 015's CPG (Joern `dominatedBy`), NOT a regex
 * over agent prose. Structural dominance proves "a check runs"; the LLM semantic
 * layer proves WHAT it asserts (right resource, right verb) so a guard that
 * dominates but authorizes the wrong operation is still flagged. Flag-gated
 * (`SHOR_GUARD_DOMINANCE`) + fail-open, so a stock scan is unchanged.
 */

export {
	guardDominanceEnabled,
	runGuardDominance,
} from "./driver.js";
export type { GuardQueryRunner, RunGuardDominanceOptions } from "./driver.js";
export {
	buildGuardDominanceScript,
	DEFAULT_GUARD_MATCHERS,
	DEFAULT_SINK_MATCHERS,
	GUARD_CWE,
	GUARD_VULN_CLASS,
	parseGuardResults,
	structuralVerdict,
} from "./query.js";
export type { GuardQueryMatchers } from "./query.js";
export {
	classifyGuard,
	createGuardSemanticAsk,
	guardSemanticEnabled,
	validateGuards,
} from "./semantic.js";
export type { GuardSemanticAsk, ValidateGuardsOptions } from "./semantic.js";
export type {
	GuardCandidate,
	GuardDisposition,
	GuardDominanceDegradation,
	GuardDominanceResult,
	GuardFinding,
	GuardRawResult,
	GuardRawSink,
	GuardSemanticVerdict,
	GuardStructuralVerdict,
} from "./types.js";
