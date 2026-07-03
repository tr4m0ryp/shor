// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Public surface of the white-box SQL query-log oracle (T8 / F14).
 *
 * A flag-gated proof + FP-demotion path: mint a `/* shor-<uuid> *​/` marker, fire it
 * into a payload, then tail the target DB's query log to see whether it landed inline
 * in a statement (INJECTED) or only as a bound parameter (PARAMETERIZED → demote).
 * Disabled by default; enabled only when `SHOR_QUERY_LOG_PATH` points at a readable
 * DB log. NOT wired into `signal.decide()` / `oracle/index.ts` — task 008 consumes
 * {@link QueryLogVerdict} and integrates it there.
 */

export {
	classifyRecords,
	createQueryLogOracle,
	loadQueryLogConfig,
	mintMarker,
	observeMarker,
	QUERY_LOG_DIALECT_ENV,
	QUERY_LOG_MAX_BYTES_ENV,
	QUERY_LOG_PATH_ENV,
	queryLogOracleEnabled,
} from "./oracle.js";
export type { ObserveOptions, QueryLogOracle } from "./oracle.js";
export {
	DEFAULT_MAX_WINDOW_BYTES,
	dialectSupported,
	fileLogSource,
	parsePostgresRecords,
	parseRecords,
	pollOnce,
	QueryLogReader,
} from "./reader.js";
export type {
	LogDialect,
	LogRecord,
	LogRecordKind,
	LogSource,
	PollResult,
	QueryLogConfig,
	QueryLogMarker,
	QueryLogVerdict,
	ReaderCursor,
	ScanResult,
	TailPoller,
} from "./types.js";
