// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
 *   - *-vuln      minCount = HALF of the category's recommended tool set, rounded
 *                 up (e.g. injection 8→4, xss 6→3, the 3-tool categories →2). A
 *                 flat floor of 2 let an 8-tool category "pass" on a quarter of
 *                 its kit; scaling to the recommended set keeps breadth honest.
 *   - *-exploit   minCount 1
 *   - `required = []` for every agent: each exploit category has several valid
 *     tools, so a hard-fail would burn a retry on a false negative. Breadth is
 *     driven by `minCount` + the continuation loop, not by hard requirements.
 *   - report & attack-surface have NO entry → `evaluateCoverage` returns
 *     `{ ok: true }` (synthesis agents run no offensive tools).
 */

import type { AgentName } from "../../types/agents.js";
import { RECOMMENDED } from "../prompt-manager/skill-recommendations.js";
import type { CoveragePolicy } from "./types.js";

/** Maximum number of in-process coverage continuation rounds per agent. */
export const MAX_COVERAGE_ROUNDS = 2;

/**
 * Maximum number of findings-discovery continuation rounds per agent (task 007
 * — loop-until-dry). ABOVE the breadth floor, the loop keeps re-prompting while
 * each round still yields a NEW finding; this is the hard ceiling so a target
 * that keeps dribbling findings cannot loop unbounded. It is >=
 * `MAX_COVERAGE_ROUNDS`: breadth is reached first (bounded by that), then up to
 * this many continuations drive findings to convergence (the loop reports — does
 * NOT silently truncate — when this cap, rather than a dry round, stops it).
 */
export const MAX_DISCOVERY_ROUNDS = 4;

/**
 * Discovery lenses cycled across continuation rounds (task 007). Each round
 * adopts the next lens so successive passes attack the SAME target from a
 * different angle — by endpoint, by tainted dataflow, by component, by prior
 * exploit history — accumulating into the same queue. Sized to
 * `MAX_DISCOVERY_ROUNDS` so every round gets a distinct angle before repeating.
 */
export const DISCOVERY_LENSES: readonly string[] = [
	"by-endpoint",
	"by-taint",
	"by-component",
	"by-history",
];

/** Policy body minus `candidates` (which is derived from `RECOMMENDED`). */
type PolicyThresholds = Pick<CoveragePolicy, "required" | "minCount">;

const EXPLOIT_MIN_COUNT = 1;

/**
 * The vuln breadth floor for a category: half its recommended tool set, rounded
 * up, floored at 1. Keyed by PROMPT name (`vuln-injection`) to match
 * `RECOMMENDED`; stays in lockstep with the candidate pool `evaluate.ts` derives
 * from the same map, so the floor can never exceed the tools that count.
 */
function vulnFloor(promptKey: string): number {
	const n = RECOMMENDED[promptKey]?.length ?? 0;
	return Math.max(1, Math.ceil(n / 2));
}

/** No agent hard-requires a specific tool by default (see header). */
const NO_REQUIRED: readonly string[] = [];

/**
 * Per-agentName thresholds. Agents absent from this map (report,
 * attack-surface) have no coverage expectation. All seven vuln categories —
 * `logic` and `misconfig-web` included — carry a floor + breadth continuation;
 * leaving the latter two out previously let them pass having run no tools at all.
 */
export const COVERAGE_POLICY: Readonly<
	Partial<Record<AgentName, PolicyThresholds>>
> = Object.freeze({
	"pre-recon": { required: NO_REQUIRED, minCount: 2 },
	recon: { required: NO_REQUIRED, minCount: 6 },
	"injection-vuln": { required: NO_REQUIRED, minCount: vulnFloor("vuln-injection") },
	"xss-vuln": { required: NO_REQUIRED, minCount: vulnFloor("vuln-xss") },
	"auth-vuln": { required: NO_REQUIRED, minCount: vulnFloor("vuln-auth") },
	"ssrf-vuln": { required: NO_REQUIRED, minCount: vulnFloor("vuln-ssrf") },
	"authz-vuln": { required: NO_REQUIRED, minCount: vulnFloor("vuln-authz") },
	"logic-vuln": { required: NO_REQUIRED, minCount: vulnFloor("vuln-logic") },
	"misconfig-web-vuln": {
		required: NO_REQUIRED,
		minCount: vulnFloor("vuln-misconfig-web"),
	},
	"injection-exploit": { required: NO_REQUIRED, minCount: EXPLOIT_MIN_COUNT },
	"xss-exploit": { required: NO_REQUIRED, minCount: EXPLOIT_MIN_COUNT },
	"auth-exploit": { required: NO_REQUIRED, minCount: EXPLOIT_MIN_COUNT },
	"ssrf-exploit": { required: NO_REQUIRED, minCount: EXPLOIT_MIN_COUNT },
	"authz-exploit": { required: NO_REQUIRED, minCount: EXPLOIT_MIN_COUNT },
});
