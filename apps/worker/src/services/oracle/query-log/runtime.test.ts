// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Injected-dependency tests for the query-log runtime: rotation/truncation-safe
 * tailing, the bounded observe loop, and flag-gated config resolution.
 */

import { describe, expect, it } from "vitest";
import {
	createQueryLogOracle,
	loadQueryLogConfig,
	observeMarker,
	pollOnce,
	QueryLogReader,
	queryLogOracleEnabled,
} from "./index.js";
import type { LogSource, PollResult, ReaderCursor, TailPoller } from "./types.js";

const TOK = "shor-11111111-2222-3333-4444-555555555555";
const PREFIX = "2026-07-03 12:00:00.000 UTC [123]";

/** Simple protocol: a string-concatenated query — marker lands inline in the SQL. */
const INLINE_LOG = `${PREFIX} LOG:  statement: SELECT * FROM users WHERE name = 'x' OR '1'='1' /* ${TOK} */`;
/** Extended protocol: parameterized — marker only in the bound parameter value. */
const PARAM_LOG = [
	`${PREFIX} LOG:  execute <unnamed>: SELECT * FROM users WHERE name = $1`,
	`${PREFIX} DETAIL:  parameters: $1 = 'x'' OR ''1''=''1 /* ${TOK} */'`,
].join("\n");

/** A controllable in-memory {@link LogSource} with rotation/failure switches. */
function memSource() {
	let content = "";
	let identity: string | undefined = "inode-a";
	let statFails = false;
	let readFails = false;
	const source: LogSource = {
		stat() {
			if (statFails) return undefined;
			const size = Buffer.byteLength(content);
			return identity === undefined ? { size } : { size, identity };
		},
		readRange(from, to) {
			return readFails ? undefined : Buffer.from(content).subarray(from, to).toString("utf8");
		},
	};
	return {
		source,
		set: (s: string) => {
			content = s;
		},
		setIdentity: (i: string | undefined) => {
			identity = i;
		},
		failStat: (b: boolean) => {
			statFails = b;
		},
		failRead: (b: boolean) => {
			readFails = b;
		},
	};
}

describe("pollOnce / QueryLogReader tailing", () => {
	it("reads only the new tail bytes and advances the offset", () => {
		const m = memSource();
		m.set("first\n");
		const reader = new QueryLogReader(m.source);
		expect(reader.poll()).toMatchObject({ available: true, chunk: "first\n" });
		expect(reader.poll()).toMatchObject({ available: true, chunk: "" }); // no new data
		m.set("first\nsecond\n");
		expect(reader.poll()).toMatchObject({ available: true, chunk: "second\n" });
	});

	it("resets to 0 on truncation (size shrank below the offset)", () => {
		const m = memSource();
		m.set("bb"); // truncated from a previously larger file
		const cursor: ReaderCursor = { offset: 10, identity: "inode-a" };
		expect(pollOnce(m.source, cursor, 1 << 20)).toMatchObject({ available: true, chunk: "bb" });
	});

	it("resets to 0 on rotation (file identity changed)", () => {
		const m = memSource();
		m.set("brand new file contents");
		m.setIdentity("inode-b");
		const cursor: ReaderCursor = { offset: 5, identity: "inode-a" };
		expect(pollOnce(m.source, cursor, 1 << 20)).toMatchObject({
			available: true,
			chunk: "brand new file contents",
		});
	});

	it("caps a huge burst to the bounded window (drops oldest bytes)", () => {
		const m = memSource();
		m.set("0123456789");
		expect(pollOnce(m.source, { offset: 0 }, 4)).toMatchObject({ available: true, chunk: "6789" });
	});

	it("reports unavailable (cursor untouched) when stat fails", () => {
		const m = memSource();
		m.set("data");
		m.failStat(true);
		const cursor: ReaderCursor = { offset: 2, identity: "inode-a" };
		const res = pollOnce(m.source, cursor, 1 << 20);
		expect(res.available).toBe(false);
		expect(res.cursor).toEqual(cursor);
	});

	it("reports unavailable (offset not advanced) when the ranged read fails", () => {
		const m = memSource();
		m.set("some new data");
		m.failRead(true);
		const res = pollOnce(m.source, { offset: 0, identity: "inode-a" }, 1 << 20);
		expect(res.available).toBe(false);
		expect(res.cursor.offset).toBe(0);
	});
});

/** A scripted poller returning queued results, then permanently empty-available. */
function scriptedPoller(results: PollResult[]): TailPoller {
	let i = 0;
	return {
		poll() {
			const r = results[i];
			if (r) {
				i += 1;
				return r;
			}
			return { available: true, chunk: "", cursor: { offset: 0 } };
		},
	};
}

const avail = (chunk: string): PollResult => ({ available: true, chunk, cursor: { offset: 0 } });
const unavail = (): PollResult => ({ available: false, cursor: { offset: 0 } });

describe("observeMarker", () => {
	const single = { timeoutMs: 0, now: () => 1000, sleep: async () => {} };

	it("inline chunk => injected", async () => {
		const reader = scriptedPoller([avail(INLINE_LOG)]);
		expect(await observeMarker(TOK, { reader, dialect: "postgres", ...single })).toBe("injected");
	});

	it("bound-parameter chunk => parameterized", async () => {
		const reader = scriptedPoller([avail(PARAM_LOG)]);
		expect(await observeMarker(TOK, { reader, dialect: "postgres", ...single })).toBe("parameterized");
	});

	it("readable but marker never appears => not_found", async () => {
		const reader = scriptedPoller([avail("LOG:  statement: SELECT 1")]);
		expect(await observeMarker(TOK, { reader, dialect: "postgres", ...single })).toBe("not_found");
	});

	it("log never readable => unavailable (never a false negative)", async () => {
		const reader = scriptedPoller([unavail()]);
		expect(await observeMarker(TOK, { reader, dialect: "postgres", ...single })).toBe("unavailable");
	});

	it("unsupported dialect => unavailable without touching the reader", async () => {
		let polled = false;
		const reader: TailPoller = {
			poll() {
				polled = true;
				return unavail();
			},
		};
		expect(await observeMarker(TOK, { reader, dialect: "mysql", ...single })).toBe("unavailable");
		expect(polled).toBe(false);
	});

	it("re-polls across the window until the marker surfaces", async () => {
		let clock = 0;
		const reader = scriptedPoller([avail(""), avail(""), avail(PARAM_LOG)]);
		const verdict = await observeMarker(TOK, {
			reader,
			dialect: "postgres",
			timeoutMs: 100,
			intervalMs: 30,
			now: () => clock,
			sleep: async (ms) => {
				clock += ms;
			},
		});
		expect(verdict).toBe("parameterized");
	});
});

describe("config gating (default-OFF)", () => {
	it("is disabled with no SHOR_QUERY_LOG_PATH set", () => {
		expect(loadQueryLogConfig({})).toBeUndefined();
		expect(queryLogOracleEnabled({})).toBe(false);
		expect(createQueryLogOracle(undefined)).toBeUndefined();
	});

	it("enables with a path and defaults the dialect to postgres", () => {
		const cfg = loadQueryLogConfig({ SHOR_QUERY_LOG_PATH: "/var/log/pg.log" });
		expect(cfg).toMatchObject({ path: "/var/log/pg.log", dialect: "postgres" });
		expect(queryLogOracleEnabled({ SHOR_QUERY_LOG_PATH: "/var/log/pg.log" })).toBe(true);
	});

	it("honors an explicit dialect override and a window override", () => {
		const cfg = loadQueryLogConfig({
			SHOR_QUERY_LOG_PATH: "/x",
			SHOR_QUERY_LOG_DIALECT: "MariaDB",
			SHOR_QUERY_LOG_MAX_BYTES: "2048",
		});
		expect(cfg).toMatchObject({ dialect: "mariadb", maxWindowBytes: 2048 });
	});

	it("builds a working oracle from a resolved config", () => {
		const oracle = createQueryLogOracle({ path: "/x", dialect: "postgres", maxWindowBytes: 1024 });
		expect(oracle?.mint().token).toMatch(/^shor-/);
	});
});
