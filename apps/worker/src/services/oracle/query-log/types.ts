// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Shared types for the white-box SQL query-log oracle (T8 / F14).
 *
 * The oracle mints a unique marker, the caller fires a marked request, and the
 * oracle tails the target DB's own query log to see WHERE the marker landed:
 *   - inline in the statement text   => the payload became executable SQL (INJECTED)
 *   - only as a bound parameter value => the query was parameterized (FP-DEMOTION)
 *
 * PII boundary: log lines carry secrets. Raw log text lives ONLY in memory during
 * a scan and is NEVER persisted or logged — every persisted/emitted value here is a
 * verdict or a count, never a captured statement.
 */

/** The DB whose query log we parse. Postgres is implemented; others are seams. */
export type LogDialect = "postgres" | "mysql" | "mariadb";

/**
 * The oracle's classification for one marked attempt.
 *   - `injected`      — marker appeared inline in statement text (strong VULN signal).
 *   - `parameterized` — marker appeared ONLY as a bound parameter (FP-demotion signal).
 *   - `not_found`     — the log was readable but the marker never surfaced in the window.
 *   - `unavailable`   — the log could not be read / dialect unsupported (never a false
 *                       negative: absence of access must not read as "not vulnerable").
 */
export type QueryLogVerdict = "injected" | "parameterized" | "not_found" | "unavailable";

/** A minted, single-use correlation marker. */
export interface QueryLogMarker {
	/** Full SQL-comment form to inject into a payload, e.g. the token wrapped in `/*` … `*​/`. */
	marker: string;
	/** The bare `shor-<uuid>` token searched for in the log (survives comment stripping). */
	token: string;
}

/** How a parsed log record relates to statement structure. */
export type LogRecordKind = "statement" | "parameter" | "other";

/**
 * One parsed log record. `text` is transient in-memory content — NEVER persisted.
 *   - `statement` — SQL text the server executed (`statement:`/`execute`/`bind`/`STATEMENT:`).
 *   - `parameter` — a bound parameter value (`DETAIL:  parameters: $n = '…'`).
 *   - `other`     — any other line (severity context, errors, unrelated detail).
 */
export interface LogRecord {
	kind: LogRecordKind;
	text: string;
}

/**
 * Pure classification of a log chunk for one marker. Carries NO raw log content
 * (PII boundary) — only counts + the derived verdict.
 */
export interface ScanResult {
	/** Never `unavailable`: a pure chunk scan can only see injected/parameterized/not_found. */
	verdict: Exclude<QueryLogVerdict, "unavailable">;
	/** Occurrences of the marker inline in statement text (executed as SQL). */
	inlineCount: number;
	/** Occurrences of the marker only as a bound parameter value (parameterized). */
	paramCount: number;
}

/** Rotation/truncation-safe tail cursor: a byte offset plus opaque file identity. */
export interface ReaderCursor {
	/** Bytes already consumed from the current file. */
	offset: number;
	/** Opaque inode-ish identity; a change between polls ⇒ rotation ⇒ reset to 0. */
	identity?: string;
}

/**
 * Injected, unit-testable view of the underlying log file. The real implementation
 * is fs-backed (`fileLogSource`); tests supply a fake.
 */
export interface LogSource {
	/** Current byte length + opaque identity; `undefined` ⇒ unreadable (unavailable). */
	stat(): { size: number; identity?: string } | undefined;
	/** Read bytes `[from, to)` as UTF-8; `undefined` ⇒ the read failed. */
	readRange(from: number, to: number): string | undefined;
}

/** Outcome of one tail poll. `available:false` ⇒ the log could not be read this time. */
export type PollResult =
	| { available: true; chunk: string; cursor: ReaderCursor }
	| { available: false; cursor: ReaderCursor };

/** Anything that yields the next tail chunk on demand — `QueryLogReader` or a test fake. */
export interface TailPoller {
	poll(): PollResult;
}

/** Resolved query-log access configuration (built from env; absent ⇒ oracle OFF). */
export interface QueryLogConfig {
	/** Filesystem path to the target DB query log the worker can read. */
	path: string;
	/** Which dialect's log format to parse. */
	dialect: LogDialect;
	/** Max bytes read per poll — the bounded window; older bytes are dropped. */
	maxWindowBytes: number;
}
