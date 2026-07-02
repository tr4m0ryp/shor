// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Oracle phase (post-exploitation adjudication) — T9 executable oracle.
 *
 * The two entry points the pipeline calls:
 *   - `runOraclePhase(ctx)` runs as a post-exploitation pipeline phase. It reads
 *     each `{category}_poc.json` the exploit agents wrote, DETERMINISTICALLY
 *     re-executes every replayable PoC (HTTP via the guarded `fetch`; browser /
 *     OOB via pluggable seams), and writes the authoritative `{ id -> disposition }`
 *     to `oracle_dispositions.json`. The verdict is EXECUTABLE — observed from a
 *     re-run — not parsed from prose.
 *   - `applyOracleDispositions(vulns, …)` runs inside `collectFindings`, after the
 *     markdown evidence parse + screen verdicts: it overlays the oracle's verdict
 *     onto the normalized queue, OVERRIDING the markdown-parsed disposition for any
 *     finding the oracle could replay, and stamps `oracle_disposition` so the
 *     finding record carries the executable outcome.
 *
 * `AgentContext` is imported type-only from the pipeline, so there is no runtime
 * dependency back into `job/pipeline` (the import is erased) and no import cycle.
 */

import type { NormalizedVuln, OracleDisposition } from "../../job/findings/types.js";
import type { AgentContext } from "../../job/pipeline.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { lookupByVulnId, lookupDisposition, readDispositions, readPremise, runOracleReplay } from "./replay/index.js";

/**
 * Run the post-exploitation oracle phase: replay every captured PoC and persist
 * the authoritative disposition map. Best-effort — a failure here leaves the
 * markdown-parsed dispositions in place (the oracle only ever tightens them).
 */
export async function runOraclePhase(ctx: AgentContext): Promise<void> {
	const { deliverablesPath, logger, progress } = ctx;
	// Emit phase progress under the "oracle" service marker so the dashboard's
	// Adjudication card shows running → done instead of sitting at "0/0 QUEUED"
	// (this phase runs a deterministic replay service, not a tracked LLM agent).
	const startedAt = Date.now();
	await progress.started("oracle");
	try {
		await runOracleReplay(deliverablesPath, logger);
		await progress.completed_("oracle", Date.now() - startedAt);
	} catch (err) {
		logger.error("Oracle replay phase failed; markdown dispositions remain authoritative", {
			error: err instanceof Error ? err.message : String(err),
		});
		await progress.failed("oracle", Date.now() - startedAt);
	}
}

/**
 * Overlay the executable-oracle verdicts onto the normalized queue, in place.
 *
 * For every finding the oracle could replay, its verdict is AUTHORITATIVE and
 * overrides the markdown-parsed disposition — it can promote a prose-"blocked"
 * finding to `exploited`, or demote a prose-"exploited" finding the replay could
 * not reproduce to `blocked`. A `not_replayable` verdict changes nothing (the
 * evidence.ts markdown parse remains the fallback). Every matched finding is
 * stamped with `oracle_disposition` (via `raw`) so the mapper surfaces it on the
 * record. Returns the same array for call-site chaining.
 */
export function applyOracleDispositions(
	vulns: NormalizedVuln[],
	deliverablesPath: string,
	logger: ActivityLogger,
): NormalizedVuln[] {
	const dispositions = readDispositions(deliverablesPath, logger);
	// Differential-authz premise (T1): `{ id -> premise_valid }`. May be present even
	// when no disposition was overridden, so read it independently of `dispositions`.
	const premise = readPremise(deliverablesPath, logger);
	if (dispositions.size === 0 && premise.size === 0) return vulns;

	let overridden = 0;
	let premiseStamped = 0;
	for (const vuln of vulns) {
		const premiseValid = lookupByVulnId(premise, vuln.id);
		if (premiseValid !== undefined) {
			// Carry the premise on `raw` so the §6.1 mapper surfaces it; the premise
			// GATE (not the oracle) demotes a privileged-only exploit to the appendix.
			vuln.raw.premise_valid = premiseValid;
			premiseStamped += 1;
		}
		const verdict = lookupDisposition(dispositions, vuln.id);
		if (!verdict) continue;
		// Stamp the executable outcome on the record (carried via `raw` → mapper).
		stampOracleDisposition(vuln, verdict);
		// Authoritative override for replayable verdicts; `not_replayable` is a no-op.
		if (verdict === "exploited" || verdict === "blocked") {
			if (vuln.disposition !== verdict) overridden += 1;
			vuln.disposition = verdict;
		}
	}
	if (overridden > 0) {
		logger.info("Oracle verdicts overrode markdown-parsed dispositions", { overridden });
	}
	if (premiseStamped > 0) {
		logger.info("Oracle stamped differential authz premise on findings", { premiseStamped });
	}
	return vulns;
}

/** Carry the oracle verdict on `raw` so the §6.1 mapper can emit it. */
function stampOracleDisposition(vuln: NormalizedVuln, verdict: OracleDisposition): void {
	vuln.raw.oracle_disposition = verdict;
}

export { runOracleReplay } from "./replay/index.js";
