// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Agent skill-coverage module.
 *
 * Public surface for the evaluator-optimizer coverage loop: the per-agent
 * policy, the agentName↔promptName reconciliation, and the pure evaluator.
 */

export { evaluateCoverage, policyFor } from "./evaluate.js";
export type { SkillReader } from "./evaluate.js";
export { makeQueueFindingsReader } from "./findings.js";
export type { FindingsReader } from "./findings.js";
export {
	COVERAGE_POLICY,
	DISCOVERY_LENSES,
	MAX_COVERAGE_ROUNDS,
	MAX_DISCOVERY_ROUNDS,
} from "./policy.js";
export { agentForPrompt, promptForAgent } from "./reconcile.js";
export type { CoveragePolicy, CoverageResult } from "./types.js";
