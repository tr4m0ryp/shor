// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * The white-box SQL query-log ORACLE (T8 / F14): mint a unique marker, correlate
 * the caller's fired request to the target DB's own query log, and classify the
 * marker inline-in-statement (INJECTED) vs bound-parameter-only (PARAMETERIZED →
 * FP-demotion). This module owns the marker + classification + bounded observe
 * loop + flag-gating; it does NOT wire into `signal.decide()` / `oracle/index.ts`
 * (that integration is task 008's — it consumes the {@link QueryLogVerdict} here).
 *
 * PII boundary: the reader's chunks and parsed records are scanned in memory and
 * discarded; only counts and the final verdict ever leave this module.
 */

import { randomUUID } from "node:crypto";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import { dialectSupported, fileLogSource, parseRecords, QueryLogReader } from "./reader.js";
import type {
	LogDialect,
	LogRecord,
	QueryLogConfig,
	QueryLogMarker,
	QueryLogVerdict,
	ScanResult,
	TailPoller,
} from "./types.js";

/** Env flag naming the readable DB query log; unset ⇒ the oracle is OFF (default). */
export const QUERY_LOG_PATH_ENV = "SHOR_QUERY_LOG_PATH";
/** Optional dialect override; defaults to `postgres`. */
export const QUERY_LOG_DIALECT_ENV = "SHOR_QUERY_LOG_DIALECT";
/** Optional per-poll window override (bytes). */
export const QUERY_LOG_MAX_BYTES_ENV = "SHOR_QUERY_LOG_MAX_BYTES";

const DEFAULT_MAX_BYTES = 1 << 20; // 1 MiB
const DEFAULT_TIMEOUT_MS = 4_000;
const DEFAULT_INTERVAL_MS = 250;

const NOOP_LOGGER: ActivityLogger = { info() {}, warn() {}, error() {} };
const realSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Mint a single-use correlation marker. The `token` is a UUID-scoped `shor-…` string
 * unique per attempt; `marker` wraps it in a SQL comment so it rides inside a payload
 * yet is inert if it lands in a parameterized value. Search always keys on `token`,
 * so the comment wrapper being stripped or the value being quoted does not matter.
 */
export function mintMarker(): QueryLogMarker {
	const token = `shor-${randomUUID()}`;
	return { token, marker: `/* ${token} */` };
}

/**
 * Classify parsed records for one marker (pure). Inline presence DOMINATES: a marker
 * that reached statement text proves executable injection regardless of any bound
 * copies. Marker seen ONLY as a bound parameter ⇒ parameterized (FP-demotion). A
 * marker in an `other` record (error echo / context) is deliberately NOT counted as
 * inline — the `STATEMENT:` record is the reliable errored-SQL carrier, so this stays
 * conservative and avoids false `injected` verdicts.
 */
export function classifyRecords(records: readonly LogRecord[], token: string): ScanResult {
	let inlineCount = 0;
	let paramCount = 0;
	for (const record of records) {
		if (!record.text.includes(token)) continue;
		if (record.kind === "statement") inlineCount += 1;
		else if (record.kind === "parameter") paramCount += 1;
	}
	const verdict: ScanResult["verdict"] =
		inlineCount > 0 ? "injected" : paramCount > 0 ? "parameterized" : "not_found";
	return { verdict, inlineCount, paramCount };
}

/** Injection seams for {@link observeMarker}; all optional with sane defaults. */
export interface ObserveOptions {
	reader: TailPoller;
	dialect: LogDialect;
	/** Total poll window before giving up. */
	timeoutMs?: number;
	/** Delay between polls. */
	intervalMs?: number;
	/** Injectable clock (tests pass a synchronous fake). */
	sleep?: (ms: number) => Promise<void>;
	/** Injectable wall-clock (tests pass a controllable stub). */
	now?: () => number;
	logger?: ActivityLogger;
}

/**
 * Poll the log tail for `token` over a bounded window and return the verdict.
 *   - inline seen         ⇒ `injected` (early exit — strongest signal)
 *   - only bound seen     ⇒ `parameterized`
 *   - readable, no marker ⇒ `not_found`
 *   - never readable / unsupported dialect ⇒ `unavailable` (never a false negative)
 * Only counts and the verdict are logged — never a captured statement.
 */
export async function observeMarker(token: string, opts: ObserveOptions): Promise<QueryLogVerdict> {
	const logger = opts.logger ?? NOOP_LOGGER;
	if (!dialectSupported(opts.dialect)) {
		logger.warn("Query-log oracle: dialect has no parser; verdict unavailable", { dialect: opts.dialect });
		return "unavailable";
	}
	const sleep = opts.sleep ?? realSleep;
	const now = opts.now ?? Date.now;
	const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const intervalMs = opts.intervalMs ?? DEFAULT_INTERVAL_MS;

	const deadline = now() + timeoutMs;
	let everReadable = false;
	let paramSeen = false;

	// Poll at least once even if the window is zero; then re-poll until the deadline.
	do {
		const poll = opts.reader.poll();
		if (poll.available) {
			everReadable = true;
			if (poll.chunk.length > 0) {
				const result = classifyRecords(parseRecords(poll.chunk, opts.dialect), token);
				if (result.inlineCount > 0) return "injected";
				if (result.paramCount > 0) paramSeen = true;
			}
		}
		if (now() >= deadline) break;
		await sleep(intervalMs);
	} while (now() < deadline);

	if (!everReadable) return "unavailable";
	return paramSeen ? "parameterized" : "not_found";
}

/**
 * Resolve query-log access from the environment. Returns `undefined` when no log
 * path is configured — the default-OFF gate: a stock scan with no new env flags does
 * not touch this oracle at all.
 */
export function loadQueryLogConfig(env: NodeJS.ProcessEnv = process.env): QueryLogConfig | undefined {
	const path = env[QUERY_LOG_PATH_ENV]?.trim();
	if (!path) return undefined;
	const raw = env[QUERY_LOG_DIALECT_ENV]?.trim().toLowerCase();
	const dialect: LogDialect = raw === "mysql" ? "mysql" : raw === "mariadb" ? "mariadb" : "postgres";
	const maxWindowBytes = Number(env[QUERY_LOG_MAX_BYTES_ENV]) || DEFAULT_MAX_BYTES;
	return { path, dialect, maxWindowBytes };
}

/** Whether the query-log oracle is configured (flag-gated). */
export function queryLogOracleEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
	return loadQueryLogConfig(env) !== undefined;
}

/** A minter + observer bound to a resolved config: task 008's integration entry point. */
export interface QueryLogOracle {
	mint(): QueryLogMarker;
	/** Fire your marked request, THEN await this to classify what the DB logged. */
	observe(
		token: string,
		over?: Partial<Pick<ObserveOptions, "timeoutMs" | "intervalMs">>,
	): Promise<QueryLogVerdict>;
}

/**
 * Build an oracle over a resolved {@link QueryLogConfig}. Each `observe` opens a fresh
 * reader (fresh byte cursor) so concurrent markers never share tail state. Returns
 * `undefined` when no config is present (the oracle stays disabled).
 */
export function createQueryLogOracle(
	config: QueryLogConfig | undefined = loadQueryLogConfig(),
	logger: ActivityLogger = NOOP_LOGGER,
): QueryLogOracle | undefined {
	if (!config) return undefined;
	return {
		mint: mintMarker,
		observe(token, over = {}) {
			const reader = new QueryLogReader(fileLogSource(config.path), config.maxWindowBytes);
			return observeMarker(token, {
				reader,
				dialect: config.dialect,
				logger,
				...(over.timeoutMs !== undefined && { timeoutMs: over.timeoutMs }),
				...(over.intervalMs !== undefined && { intervalMs: over.intervalMs }),
			});
		},
	};
}
