// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Query-log READER: a rotation/truncation-safe byte-offset tail plus a dialect
 * parser that turns a raw log chunk into typed {@link LogRecord}s.
 *
 * `pollOnce`/{@link QueryLogReader} advance a {@link ReaderCursor} across polls:
 *   - identity change (inode-ish id differs)  ⇒ the file was rotated  ⇒ reset to 0
 *   - size shrank below the offset            ⇒ the file was truncated ⇒ reset to 0
 *   - a bounded window caps bytes-per-poll so a huge burst cannot exhaust memory
 * A stat/read failure is reported as `available:false` (the oracle maps that to the
 * `unavailable` verdict — never a false negative) and leaves the cursor untouched.
 *
 * The parser is Postgres-first (`log_statement=all`, simple + extended protocol);
 * MySQL/MariaDB are documented seams that return `[]` so the oracle stays honest
 * (an unsupported dialect resolves to `unavailable`, not a false `not_found`).
 */

import fs from "node:fs";
import type { LogDialect, LogRecord, LogSource, PollResult, ReaderCursor } from "./types.js";

/** Default per-poll window: read at most this many trailing bytes. */
export const DEFAULT_MAX_WINDOW_BYTES = 1 << 20; // 1 MiB

/** fs-backed {@link LogSource}: `stat` for size + inode identity, ranged reads. */
export function fileLogSource(filePath: string): LogSource {
	return {
		stat() {
			try {
				const st = fs.statSync(filePath);
				return { size: st.size, identity: `${st.dev}:${st.ino}` };
			} catch {
				return undefined;
			}
		},
		readRange(from, to) {
			if (to <= from) return "";
			const len = to - from;
			let fd: number | undefined;
			try {
				fd = fs.openSync(filePath, "r");
				const buf = Buffer.allocUnsafe(len);
				const read = fs.readSync(fd, buf, 0, len, from);
				return buf.subarray(0, read).toString("utf8");
			} catch {
				return undefined;
			} finally {
				if (fd !== undefined) {
					try {
						fs.closeSync(fd);
					} catch {
						/* best-effort close */
					}
				}
			}
		},
	};
}

/** Build a {@link ReaderCursor}, omitting `identity` when absent (exactOptionalPropertyTypes). */
function cursorOf(offset: number, identity: string | undefined): ReaderCursor {
	return identity === undefined ? { offset } : { offset, identity };
}

/**
 * Read the new tail bytes since {@link cursor}, handling rotation, truncation, and a
 * bounded window. Pure over the injected {@link LogSource} — deterministic and
 * unit-testable without a live file.
 */
export function pollOnce(source: LogSource, cursor: ReaderCursor, maxWindowBytes: number): PollResult {
	const st = source.stat();
	if (!st) return { available: false, cursor };

	const rotated =
		cursor.identity !== undefined && st.identity !== undefined && st.identity !== cursor.identity;
	const truncated = st.size < cursor.offset;
	let from = rotated || truncated ? 0 : cursor.offset;

	// Bounded window: never read more than the cap; drop the oldest bytes.
	if (st.size - from > maxWindowBytes) from = st.size - maxWindowBytes;

	const next = cursorOf(st.size, st.identity);
	if (st.size <= from) return { available: true, chunk: "", cursor: next };

	const chunk = source.readRange(from, st.size);
	if (chunk === undefined) return { available: false, cursor };
	return { available: true, chunk, cursor: next };
}

/** Stateful tail: wraps a {@link LogSource} and advances its cursor on each poll. */
export class QueryLogReader {
	private cursor: ReaderCursor = { offset: 0 };

	constructor(
		private readonly source: LogSource,
		private readonly maxWindowBytes: number = DEFAULT_MAX_WINDOW_BYTES,
	) {}

	/** Advance the tail and return the new chunk (or an `available:false` failure). */
	poll(): PollResult {
		const result = pollOnce(this.source, this.cursor, this.maxWindowBytes);
		this.cursor = result.cursor;
		return result;
	}
}

/** Postgres severities whose message body we anchor on (`log_line_prefix`-agnostic). */
const PG_SEVERITY = "(?:LOG|DETAIL|STATEMENT|ERROR|WARNING|FATAL|PANIC|NOTICE|HINT|CONTEXT)";
// Anchor on the FIRST severity tag on a line (lazy prefix): the tag always follows the
// operator's `log_line_prefix` and precedes the message, so the tag+`:` + one/two
// spaces reliably marks where the message body starts, regardless of prefix contents.
const PG_TAG_RE = new RegExp(`^.*?\\b(${PG_SEVERITY}):[ \\t]{1,2}(.*)$`);

/** Classify a Postgres message body (text after `SEVERITY:  `) into a record kind. */
function classifyPostgresBody(severity: string, body: string): LogRecord {
	// The original SQL of an errored statement is echoed under STATEMENT: — inline text.
	if (severity === "STATEMENT") return { kind: "statement", text: body };
	// Bound parameter values of an extended-protocol execute: `parameters: $1 = '…'`.
	if (severity === "DETAIL" && /^parameters:/i.test(body)) return { kind: "parameter", text: body };
	// Simple-protocol SQL and extended-protocol prepared/execute/bind text.
	if (/^statement:/i.test(body)) return { kind: "statement", text: body.replace(/^statement:\s*/i, "") };
	if (/^(?:execute|bind)\b/i.test(body)) {
		const colon = body.indexOf(": ");
		return { kind: "statement", text: colon >= 0 ? body.slice(colon + 2) : body };
	}
	return { kind: "other", text: body };
}

/**
 * Parse a Postgres `log_statement=all` chunk into records. A statement can span
 * physical lines (embedded newlines); a continuation line carries no severity tag,
 * so it is appended to the currently-open record. Only the record KIND matters to
 * the classifier — the text is scanned for the marker, never persisted.
 */
export function parsePostgresRecords(chunk: string): LogRecord[] {
	const records: LogRecord[] = [];
	let open: LogRecord | undefined;
	for (const line of chunk.split("\n")) {
		const m = PG_TAG_RE.exec(line);
		if (m) {
			if (open) records.push(open);
			open = classifyPostgresBody(m[1] as string, m[2] as string);
		} else if (open) {
			open.text += `\n${line}`; // continuation of a multi-line statement
		}
	}
	if (open) records.push(open);
	return records;
}

/**
 * Parse a raw log chunk for a dialect. Postgres is implemented; MySQL/MariaDB are
 * TODO seams (return `[]` so the oracle resolves `unavailable`, never a false clean).
 *
 * TODO(mysql): general_log rows are `Query\t<sql>` with no bound-parameter form —
 * discrimination relies on `Prepare`/`Execute` events; needs its own parser.
 * TODO(mariadb): same general_log shape; verify `Execute` argument logging first.
 */
export function parseRecords(chunk: string, dialect: LogDialect): LogRecord[] {
	if (dialect === "postgres") return parsePostgresRecords(chunk);
	return [];
}

/** Whether the given dialect has a real parser (vs. a not-yet-built seam). */
export function dialectSupported(dialect: LogDialect): boolean {
	return dialect === "postgres";
}
