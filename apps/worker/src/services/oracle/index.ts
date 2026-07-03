// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Oracle phase (post-exploitation adjudication) — T9 executable oracle + the T7
 * calibrated-gating integration (task 008).
 *
 * The two entry points the pipeline calls:
 *   - `runOraclePhase(ctx)` runs as a post-exploitation pipeline phase. It reads
 *     each `{category}_poc.json` the exploit agents wrote, DETERMINISTICALLY
 *     re-executes every replayable PoC (HTTP via the guarded `fetch`; OOB via the
 *     self-hosted-interactsh executor when `SHOR_OOB=1`), and writes the
 *     authoritative `{ id -> disposition }` to `oracle_dispositions.json`.
 *   - `applyOracleDispositions(vulns, …)` runs inside `collectFindings`. It overlays
 *     the oracle's verdict onto the normalized queue. With the calibrated-gating
 *     overlay ON (`SHOR_ORACLE_CONFIDENCE=1`) it folds the differential premise,
 *     four-way authz-matrix (005) and SQL query-log (007) verdicts into the WIDENED
 *     disposition + a calibrated confidence: promotion is fail-CLOSED (low score →
 *     `needs_review`, never a silent `exploited`); an infra outcome is
 *     `inconclusive_infra` and NEVER a refutation (fail-open on demotion).
 *
 * Everything new is flag-gated: with `SHOR_OOB` and `SHOR_ORACLE_CONFIDENCE` unset
 * a stock scan behaves EXACTLY as before.
 */

import fs from "node:fs";
import path from "node:path";
import { canonicalVulnId } from "../../job/findings/evidence.js";
import type { NormalizedVuln, OracleDisposition } from "../../job/findings/types.js";
import type { AgentContext } from "../../job/pipeline.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { combineVerdict, oracleConfidenceEnabled, type VerdictSignals } from "./confidence.js";
import type { QueryLogVerdict } from "./query-log/types.js";
import type { AuthzVerdict } from "./replay/authz-matrix.js";
import { buildExecutorSet } from "./replay/executors.js";
import { lookupByVulnId, lookupDisposition, readDispositions, readPremise, runOracleReplay } from "./replay/index.js";
import { readOobConfig, startInteractshListener } from "./replay/oob/index.js";
import type { OobListener } from "./replay/oob/index.js";
import type { ReplayDisposition } from "./replay/types.js";

/** Optional per-finding authz-matrix (005) verdicts, written by a live matrix pass. */
const ORACLE_AUTHZ_FILE = "oracle_authz.json";
/** Optional per-finding SQL query-log (007) verdicts, written by a live query-log pass. */
const ORACLE_QUERY_LOG_FILE = "oracle_query_log.json";

const AUTHZ_VERDICTS: ReadonlySet<string> = new Set<AuthzVerdict>(["bypassed", "enforced", "unknown"]);
const QUERY_LOG_VERDICTS: ReadonlySet<string> = new Set<QueryLogVerdict>([
	"injected",
	"parameterized",
	"not_found",
	"unavailable",
]);

/**
 * Start the interactsh OOB listener when `SHOR_OOB=1` (+ a server is configured) and
 * return an executor set bound to it. `undefined` ⇒ OOB is off; the caller uses the
 * default executors, so the scan is byte-identical to today. Never throws.
 */
function startOob(logger: ActivityLogger): { listener: OobListener; executors: ReturnType<typeof buildExecutorSet> } | undefined {
	const cfg = readOobConfig();
	if (!cfg) return undefined;
	const listener = startInteractshListener(cfg, logger);
	return { listener, executors: buildExecutorSet(listener) };
}

/**
 * Run the post-exploitation oracle phase: replay every captured PoC and persist
 * the authoritative disposition map. Best-effort — a failure here leaves the
 * markdown-parsed dispositions in place (the oracle only ever tightens them).
 */
export async function runOraclePhase(ctx: AgentContext): Promise<void> {
	const { deliverablesPath, logger, progress } = ctx;
	const startedAt = Date.now();
	await progress.started("oracle");
	const oob = startOob(logger);
	try {
		await runOracleReplay(deliverablesPath, logger, oob ? { executors: oob.executors } : {});
		await progress.completed_("oracle", Date.now() - startedAt);
	} catch (err) {
		logger.error("Oracle replay phase failed; markdown dispositions remain authoritative", {
			error: err instanceof Error ? err.message : String(err),
		});
		await progress.failed("oracle", Date.now() - startedAt);
	} finally {
		if (oob) await oob.listener.stop().catch(() => {});
	}
}

/** Read an optional canonical-id-keyed verdict map, validating each value. */
function readVerdictMap<T extends string>(
	deliverablesPath: string,
	file: string,
	allowed: ReadonlySet<string>,
	logger: ActivityLogger,
): Map<string, T> {
	const out = new Map<string, T>();
	const full = path.join(deliverablesPath, file);
	try {
		if (!fs.existsSync(full)) return out;
		const parsed: unknown = JSON.parse(fs.readFileSync(full, "utf8"));
		if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return out;
		for (const [id, v] of Object.entries(parsed as Record<string, unknown>)) {
			if (typeof v === "string" && allowed.has(v)) out.set(canonicalVulnId(id), v as T);
		}
	} catch (err) {
		logger.warn("Oracle: failed to read optional verdict file; skipping", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
	}
	return out;
}

/** Carry the (narrow) oracle verdict on `raw` so the §6.1 mapper can emit it. */
function stampOracleDisposition(vuln: NormalizedVuln, verdict: OracleDisposition): void {
	vuln.raw.oracle_disposition = verdict;
}

/**
 * Apply a widened, calibrated verdict to one finding (gating overlay ON).
 *   - `exploited` / `blocked` — authoritative override (as today).
 *   - `inconclusive_infra`    — NO override (fail-open: never a refutation).
 *   - `needs_review`          — fail-closed: never promote; demote a would-be
 *     confirmed exploit out of the emitted set by invalidating its premise, which
 *     the premise gate + scoring route to the manual-review appendix.
 * Returns whether it overrode the disposition (for the tally).
 */
function applyCombined(
	vuln: NormalizedVuln,
	disposition: ReplayDisposition,
	baseVerdict: OracleDisposition | undefined,
): boolean {
	if (disposition === "exploited" || disposition === "blocked") {
		const changed = vuln.disposition !== disposition;
		vuln.disposition = disposition;
		return changed;
	}
	if (disposition === "needs_review") {
		// Hold a low-confidence positive for review; do not silently emit it.
		if (vuln.disposition === "exploited" || baseVerdict === "exploited") {
			vuln.premise_valid = false;
			vuln.raw.premise_valid = false;
		}
	}
	// `inconclusive_infra` (and a needs_review on a non-exploited finding) leave the
	// markdown disposition untouched — the infra/inconclusive outcome never refutes.
	return false;
}

/**
 * Overlay the executable-oracle verdicts onto the normalized queue, in place.
 *
 * With the calibrated-gating overlay OFF (default) this is the historical behavior:
 * a replayable `exploited`/`blocked` verdict is authoritative, `not_replayable` is a
 * no-op, and the differential premise is stamped on `raw`. With the overlay ON, the
 * premise / authz-matrix / query-log verdicts are folded into a widened, calibrated
 * disposition per {@link combineVerdict}. Returns the same array for chaining.
 */
export function applyOracleDispositions(
	vulns: NormalizedVuln[],
	deliverablesPath: string,
	logger: ActivityLogger,
): NormalizedVuln[] {
	const dispositions = readDispositions(deliverablesPath, logger);
	const premise = readPremise(deliverablesPath, logger);
	const gating = oracleConfidenceEnabled();
	const authz = gating
		? readVerdictMap<AuthzVerdict>(deliverablesPath, ORACLE_AUTHZ_FILE, AUTHZ_VERDICTS, logger)
		: new Map<string, AuthzVerdict>();
	const queryLog = gating
		? readVerdictMap<QueryLogVerdict>(deliverablesPath, ORACLE_QUERY_LOG_FILE, QUERY_LOG_VERDICTS, logger)
		: new Map<string, QueryLogVerdict>();
	if (dispositions.size === 0 && premise.size === 0 && authz.size === 0 && queryLog.size === 0) return vulns;

	let overridden = 0;
	let premiseStamped = 0;
	let gated = 0;
	let infra = 0;
	for (const vuln of vulns) {
		const premiseValid = lookupByVulnId(premise, vuln.id);
		if (premiseValid !== undefined) {
			vuln.raw.premise_valid = premiseValid;
			premiseStamped += 1;
		}
		const verdict = lookupDisposition(dispositions, vuln.id);

		if (!gating) {
			// Historical path — byte-identical to before the confidence overlay.
			if (!verdict) continue;
			stampOracleDisposition(vuln, verdict);
			if (verdict === "exploited" || verdict === "blocked") {
				if (vuln.disposition !== verdict) overridden += 1;
				vuln.disposition = verdict;
			}
			continue;
		}

		// Bridge the differential-authz premise to the TYPED field so the (otherwise
		// dormant) premise gate + scoring demote a privileged-only "exploit" — the
		// god-mode false-positive class. Only under the flag ⇒ stock behavior intact.
		if (premiseValid === false) vuln.premise_valid = false;

		const authzVerdict = lookupByVulnId(authz, vuln.id);
		const queryLogVerdict = lookupByVulnId(queryLog, vuln.id);
		if (verdict === undefined && premiseValid === undefined && authzVerdict === undefined && queryLogVerdict === undefined) {
			continue;
		}
		if (verdict) stampOracleDisposition(vuln, verdict);
		const signals: VerdictSignals = {
			base: verdict ?? "not_replayable",
			...(premiseValid !== undefined && { premiseValid }),
			...(authzVerdict !== undefined && { authz: authzVerdict }),
			...(queryLogVerdict !== undefined && { queryLog: queryLogVerdict }),
			...(vuln.in_scope !== undefined && { inScope: vuln.in_scope }),
		};
		const combined = combineVerdict(signals);
		vuln.raw.oracle_replay_disposition = combined.disposition;
		vuln.raw.oracle_confidence = combined.score;
		if (applyCombined(vuln, combined.disposition, verdict)) overridden += 1;
		if (combined.disposition === "needs_review") gated += 1;
		if (combined.disposition === "inconclusive_infra") infra += 1;
	}
	if (overridden > 0) logger.info("Oracle verdicts overrode markdown-parsed dispositions", { overridden });
	if (premiseStamped > 0) logger.info("Oracle stamped differential authz premise on findings", { premiseStamped });
	if (gated > 0) logger.info("Oracle gated low-confidence exploits to needs_review", { gated });
	if (infra > 0) logger.info("Oracle marked replays inconclusive_infra (not a refutation)", { infra });
	return vulns;
}

export { runOracleReplay } from "./replay/index.js";
