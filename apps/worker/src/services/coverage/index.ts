// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Agent skill-coverage module.
 *
 * Public surface for the evaluator-optimizer coverage loop: the per-agent
 * policy, the agentName↔promptName reconciliation, and the pure evaluator.
 */

export type { SkillReader } from "./evaluate.js";
export { evaluateCoverage, policyFor } from "./evaluate.js";
export type { FindingsReader } from "./findings.js";
export { makeQueueFindingsReader } from "./findings.js";
export {
	COVERAGE_POLICY,
	DISCOVERY_LENSES,
	MAX_COVERAGE_ROUNDS,
	MAX_DISCOVERY_ROUNDS,
} from "./policy.js";
export { agentForPrompt, promptForAgent } from "./reconcile.js";
export type {
	CoveragePolicy,
	CoverageResult,
	CoverageShortfall,
} from "./types.js";
