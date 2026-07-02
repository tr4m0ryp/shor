// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Findings-convergence reader (task 007 — loop-until-dry).
 *
 * The discovery loop continues only while the agent keeps producing NEW
 * findings. The signal is the length of the agent's on-disk exploitation queue
 * (`{category}_exploitation_queue.json`, shape `{ "vulnerabilities": [...] }`,
 * which the vuln agent writes itself each round). A `FindingsReader` returns the
 * CURRENT queue length so the loop can diff it against the prior round; a
 * round that adds nothing new is the convergence (dry) signal.
 *
 * Reads are CONFINED to the deliverables directory and are best-effort:
 *   - a number   → that vuln agent's queue currently holds that many entries
 *     (a missing or malformed file degrades to 0 — a clean negative is valid);
 *   - `undefined`→ the agent has no exploitation queue (non-vuln agent), i.e.
 *     there is no findings signal, so the loop falls back to the breadth floor.
 */

import fs from "node:fs";
import path from "node:path";
import { getQueueFilename } from "../../ai/queue-schemas.js";
import type { AgentName } from "../../types/agents.js";

/**
 * Reads the CURRENT number of findings an agent has queued on disk.
 *   - `number`    → the agent has a findings queue with that many entries
 *   - `undefined` → the agent has no findings queue (no convergence signal)
 */
export type FindingsReader = (agent: AgentName) => number | undefined;

/** Count entries in a parsed `{ "vulnerabilities": [...] }` queue, else 0. */
function countVulnerabilities(parsed: unknown): number {
	if (parsed === null || typeof parsed !== "object") return 0;
	const vulns = (parsed as { vulnerabilities?: unknown }).vulnerabilities;
	return Array.isArray(vulns) ? vulns.length : 0;
}

/**
 * Build a `FindingsReader` that reads each vuln agent's exploitation queue from
 * `deliverablesPath`. Reads are confined to that directory and never throw: a
 * missing/garbled file degrades to 0 findings, and a non-vuln agent (no queue
 * filename) yields `undefined` ("no findings signal").
 */
export function makeQueueFindingsReader(
	deliverablesPath: string,
): FindingsReader {
	return (agent) => {
		const filename = getQueueFilename(agent);
		if (!filename) return undefined; // not a vuln agent → no signal
		const filePath = path.join(deliverablesPath, filename);
		try {
			if (!fs.existsSync(filePath)) return 0;
			return countVulnerabilities(JSON.parse(fs.readFileSync(filePath, "utf8")));
		} catch {
			return 0; // unreadable/garbled → treat as no findings yet
		}
	};
}
