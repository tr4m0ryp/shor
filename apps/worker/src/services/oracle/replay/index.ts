// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Oracle replay runner (T9): re-execute each captured PoC deterministically and
 * reduce it to an authoritative `exploited` / `blocked` / `not_replayable`
 * verdict — an EXECUTABLE oracle, not a prose parse.
 *
 * Requests run SEQUENTIALLY with an inter-request delay and 429 backoff so the
 * replay never hammers a target. Only read-only PoCs are ever issued; everything
 * else is classified `not_replayable` and never re-fired.
 */

import type { OracleSummary } from "../../../ai/structured/index.js";
import { assertNetworkAllowed } from "../../../guardrails/index.js";
import type { OracleDisposition } from "../../../job/findings/types.js";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import { DEFAULT_EXECUTORS } from "./executors.js";
import { loadDifferentialIdentities, type ReplayIdentity } from "./identity-auth.js";
import { ORACLE_DISPOSITIONS_FILE, readPocFiles, writeDispositions, writePremise } from "./poc-io.js";
import { decide, type DifferentialOutcome, decidePremise, isReadOnly } from "./signal.js";
import type { ExecCtx, ExecOutcome, ExecutorSet, Poc } from "./types.js";

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_DELAY_MS = 200;
const MAX_DELAY_MS = 4_000;

/** Tunables / injection seams for {@link runReplay} (all optional; sane defaults). */
export interface ReplayOptions {
	logger?: ActivityLogger;
	executors?: ExecutorSet;
	fetchImpl?: typeof fetch;
	assertAllowed?: (url: string) => void;
	timeoutMs?: number;
	delayMs?: number;
	sleep?: (ms: number) => Promise<void>;
}

const NOOP_LOGGER: ActivityLogger = { info() {}, warn() {}, error() {} };
const realSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Replay every PoC and return one {@link OracleSummary} per finding. Pure of disk
 * I/O — callers supply the parsed PoCs and consume the verdicts.
 */
export async function runReplay(pocs: Poc[], options: ReplayOptions = {}): Promise<OracleSummary[]> {
	const logger = options.logger ?? NOOP_LOGGER;
	const executors = options.executors ?? DEFAULT_EXECUTORS;
	const sleep = options.sleep ?? realSleep;
	const ctx: ExecCtx = {
		fetchImpl: options.fetchImpl ?? fetch,
		assertAllowed: options.assertAllowed ?? assertNetworkAllowed,
		timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
		logger,
	};
	let delay = options.delayMs ?? DEFAULT_DELAY_MS;

	const results: OracleSummary[] = [];
	for (const poc of pocs) {
		// SAFETY GATE: state-changing PoCs are NEVER re-fired.
		if (!isReadOnly(poc)) {
			results.push({ id: poc.id, disposition: "not_replayable", signal: "state-changing PoC; not auto-replayed" });
			continue;
		}

		let outcome: ExecOutcome;
		try {
			outcome = await executors[poc.kind](poc, ctx);
		} catch (err) {
			outcome = { observed: false, reason: "error", detail: err instanceof Error ? err.message : String(err) };
		}

		const verdict = decide(poc, outcome);
		results.push({ id: poc.id, disposition: verdict.disposition, signal: verdict.signal });
		if (verdict.rateLimited) delay = Math.min(delay * 2, MAX_DELAY_MS);
		if (delay > 0) await sleep(delay);
	}
	return results;
}

/**
 * Read the PoC sidecars, replay them, and persist the authoritative verdict map
 * to `oracle_dispositions.json`. Returns the `{ id -> disposition }` map.
 */
export async function runOracleReplay(
	deliverablesPath: string,
	logger: ActivityLogger,
	options: ReplayOptions = {},
): Promise<Map<string, OracleDisposition>> {
	const pocs = readPocFiles(deliverablesPath, logger);
	const map = new Map<string, OracleDisposition>();
	if (pocs.length === 0) {
		logger.info("Oracle: no replayable PoC sidecars found; skipping replay phase");
		return map;
	}

	const summaries = await runReplay(pocs, { logger, ...options });
	for (const s of summaries) map.set(s.id, s.disposition);
	writeDispositions(deliverablesPath, map, logger);

	const tally = { exploited: 0, blocked: 0, not_replayable: 0 };
	for (const d of map.values()) tally[d] += 1;
	logger.info("Oracle replay complete", { file: ORACLE_DISPOSITIONS_FILE, total: map.size, ...tally });
	return map;
}

export { DEFAULT_EXECUTORS, httpExecutor } from "./executors.js";
export {
	ORACLE_DISPOSITIONS_FILE,
	lookupDisposition,
	parsePoc,
	readDispositions,
	readPocFiles,
	writeDispositions,
} from "./poc-io.js";
export { decide, isReadOnly, matchSignal } from "./signal.js";
export type {
	ExecCtx,
	ExecOutcome,
	Executor,
	ExecutorSet,
	ExpectedSignal,
	Poc,
	PocKind,
	PocRequest,
	SignalType,
} from "./types.js";
