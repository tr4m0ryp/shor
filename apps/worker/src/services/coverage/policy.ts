// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Per-agent coverage policy (T8 — tunable thresholds).
 *
 * Stored per **agentName**. Each entry carries only `required` and `minCount`;
 * the `candidates` pool is DERIVED at evaluation time from
 * `RECOMMENDED[promptForAgent(agent)]` (see `evaluate.ts`) so there is a single
 * source of truth and no parallel skill list to drift.
 *
 * Defaults:
 *   - recon       minCount 6
 *   - pre-recon   minCount 2
 *   - *-vuln      minCount 2
 *   - *-exploit   minCount 1
 *   - `required = []` for every agent: each exploit category has several valid
 *     tools, so a hard-fail would burn a retry on a false negative. Breadth is
 *     driven by `minCount` + the continuation loop, not by hard requirements.
 *   - report & attack-surface have NO entry → `evaluateCoverage` returns
 *     `{ ok: true }` (synthesis agents run no offensive tools).
 */

import type { AgentName } from "../../types/agents.js";
import type { CoveragePolicy } from "./types.js";

/** Maximum number of in-process coverage continuation rounds per agent. */
export const MAX_COVERAGE_ROUNDS = 2;

/** Policy body minus `candidates` (which is derived from `RECOMMENDED`). */
type PolicyThresholds = Pick<CoveragePolicy, "required" | "minCount">;

const VULN_MIN_COUNT = 2;
const EXPLOIT_MIN_COUNT = 1;

/** No agent hard-requires a specific tool by default (see header). */
const NO_REQUIRED: readonly string[] = [];

/**
 * Per-agentName thresholds. Agents absent from this map (report,
 * attack-surface) have no coverage expectation.
 */
export const COVERAGE_POLICY: Readonly<
	Partial<Record<AgentName, PolicyThresholds>>
> = Object.freeze({
	"pre-recon": { required: NO_REQUIRED, minCount: 2 },
	recon: { required: NO_REQUIRED, minCount: 6 },
	"injection-vuln": { required: NO_REQUIRED, minCount: VULN_MIN_COUNT },
	"xss-vuln": { required: NO_REQUIRED, minCount: VULN_MIN_COUNT },
	"auth-vuln": { required: NO_REQUIRED, minCount: VULN_MIN_COUNT },
	"ssrf-vuln": { required: NO_REQUIRED, minCount: VULN_MIN_COUNT },
	"authz-vuln": { required: NO_REQUIRED, minCount: VULN_MIN_COUNT },
	"injection-exploit": { required: NO_REQUIRED, minCount: EXPLOIT_MIN_COUNT },
	"xss-exploit": { required: NO_REQUIRED, minCount: EXPLOIT_MIN_COUNT },
	"auth-exploit": { required: NO_REQUIRED, minCount: EXPLOIT_MIN_COUNT },
	"ssrf-exploit": { required: NO_REQUIRED, minCount: EXPLOIT_MIN_COUNT },
	"authz-exploit": { required: NO_REQUIRED, minCount: EXPLOIT_MIN_COUNT },
});
