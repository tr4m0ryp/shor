// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Runner + disk-I/O tests: the read-only safety gate (state-changing PoCs are
 * never fired), the network guard wrapping EVERY outbound request, signal → verdict
 * end to end through the real HTTP executor, 429 backoff, and the PoC / disposition
 * round-trip on disk.
 */

import { promises as fsp } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import { readDispositions, readPocFiles, writeDispositions } from "./poc-io.js";
import { runReplay } from "./index.js";
import type { ExecOutcome, OracleDisposition, Poc } from "./types.js";

const logger = { info() {}, warn() {}, error() {} } as ActivityLogger;

/** Minimal `Response` stand-in for an injected `fetch`. */
function mockResponse(status: number, body: string): Response {
	return { status, text: async () => body } as unknown as Response;
}

/** Fast, deterministic injection seams: no real delay, no real network/guard. */
function fastOpts(over: Record<string, unknown> = {}): Record<string, unknown> {
	return { logger, delayMs: 0, timeoutMs: 0, sleep: async () => {}, ...over };
}

function httpPoc(id: string, over: Partial<Poc> = {}): Poc {
	return {
		id,
		kind: "http",
		request: { method: "GET", url: `https://target.example/${id}` },
		expected_signal: { type: "status", match: 200 },
		...over,
	};
}

const tmpDirs: string[] = [];
async function mkDeliverables(): Promise<string> {
	const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "shor-oracle-"));
	tmpDirs.push(dir);
	return dir;
}
afterEach(async () => {
	for (const d of tmpDirs.splice(0)) await fsp.rm(d, { recursive: true, force: true });
	vi.restoreAllMocks();
});

describe("runReplay safety gate", () => {
	it("NEVER fires a state-changing PoC and classifies it not_replayable", async () => {
		const fetchImpl = vi.fn(async () => mockResponse(200, "ok"));
		const assertAllowed = vi.fn();
		const pocs = [
			httpPoc("INJ-VULN-01", { request: { method: "POST", url: "https://target.example/write" } }),
			httpPoc("INJ-VULN-02"), // read-only GET — should fire
		];

		const out = await runReplay(pocs, fastOpts({ fetchImpl, assertAllowed }));

		expect(out.find((r) => r.id === "INJ-VULN-01")?.disposition).toBe("not_replayable");
		expect(out.find((r) => r.id === "INJ-VULN-02")?.disposition).toBe("exploited");
		// The POST never reached the network OR the guard; only the GET did.
		expect(fetchImpl).toHaveBeenCalledTimes(1);
		expect(assertAllowed).toHaveBeenCalledTimes(1);
		expect(assertAllowed).toHaveBeenCalledWith("https://target.example/INJ-VULN-02");
	});
});

describe("runReplay network guard", () => {
	it("calls assertNetworkAllowed before fetch for EVERY outbound request", async () => {
		const order: string[] = [];
		const assertAllowed = vi.fn((url: string) => order.push(`guard:${url}`));
		const fetchImpl = vi.fn(async (input: Parameters<typeof fetch>[0]) => {
			order.push(`fetch:${String(input)}`);
			return mockResponse(200, "ok");
		});
		const pocs = [httpPoc("A"), httpPoc("B"), httpPoc("C")];

		await runReplay(pocs, fastOpts({ fetchImpl, assertAllowed }));

		expect(assertAllowed).toHaveBeenCalledTimes(3);
		expect(fetchImpl).toHaveBeenCalledTimes(3);
		// Guard precedes its fetch for each request.
		expect(order).toEqual([
			"guard:https://target.example/A",
			"fetch:https://target.example/A",
			"guard:https://target.example/B",
			"fetch:https://target.example/B",
			"guard:https://target.example/C",
			"fetch:https://target.example/C",
		]);
	});

	it("does NOT fetch when the guard rejects the URL → not_replayable", async () => {
		const assertAllowed = vi.fn(() => {
			throw new Error("egress to internal address is blocked");
		});
		const fetchImpl = vi.fn(async () => mockResponse(200, "ok"));

		const out = await runReplay([httpPoc("SSRF-VULN-01")], fastOpts({ fetchImpl, assertAllowed }));

		expect(out[0]?.disposition).toBe("not_replayable");
		expect(fetchImpl).not.toHaveBeenCalled();
	});
});

describe("runReplay signal → verdict (real HTTP executor)", () => {
	it("reflection present → exploited; absent → blocked", async () => {
		const fetchImpl = vi.fn(async (input: Parameters<typeof fetch>[0]) =>
			String(input).endsWith("hit")
				? mockResponse(200, "<svg/onload=alert(1)>")
				: mockResponse(200, "safely &lt;encoded&gt;"),
		);
		const reflect: Poc["expected_signal"] = { type: "reflection", match: "<svg/onload=alert(1)>" };
		const pocs = [
			httpPoc("hit", { expected_signal: reflect }),
			httpPoc("miss", { expected_signal: reflect }),
		];

		const out = await runReplay(pocs, fastOpts({ fetchImpl, assertAllowed: vi.fn() }));

		expect(out.find((r) => r.id === "hit")?.disposition).toBe("exploited");
		expect(out.find((r) => r.id === "miss")?.disposition).toBe("blocked");
	});

	it("HTTP 429 → not_replayable (rate-limited, not blocked)", async () => {
		const fetchImpl = vi.fn(async () => mockResponse(429, "slow down"));
		const out = await runReplay([httpPoc("X")], fastOpts({ fetchImpl, assertAllowed: vi.fn() }));
		expect(out[0]?.disposition).toBe("not_replayable");
	});
});

describe("runReplay executor dispatch", () => {
	it("routes by kind and defaults browser / oob to not_replayable", async () => {
		const pocs: Poc[] = [
			{ id: "XSS-1", kind: "browser", browser_script: "x", expected_signal: { type: "reflection", match: "a" }, safe: true },
			{ id: "SSRF-1", kind: "oob", expected_signal: { type: "oob", match: "tok" }, safe: true },
		];
		const out = await runReplay(pocs, fastOpts());
		expect(out.every((r) => r.disposition === "not_replayable")).toBe(true);
	});
});

describe("poc-io round-trip", () => {
	it("writes then reads back the disposition map (canonicalized keys)", async () => {
		const dir = await mkDeliverables();
		const map = new Map<string, OracleDisposition>([
			["INJ-VULN-01", "exploited"],
			["AUTH-VULN-2", "blocked"],
		]);
		writeDispositions(dir, map, logger);

		const back = readDispositions(dir, logger);
		expect(back.get("INJ-VULN-1")).toBe("exploited"); // canonical (zero-pad stripped)
		expect(back.get("AUTH-VULN-2")).toBe("blocked");
	});

	it("parses a written *_poc.json, skipping malformed entries", async () => {
		const dir = await mkDeliverables();
		await fsp.writeFile(
			path.join(dir, "injection_poc.json"),
			JSON.stringify([
				{ id: "INJ-VULN-01", kind: "http", request: { method: "GET", url: "https://t/x" }, expected_signal: { type: "status", match: 200 } },
				{ id: "", kind: "http", expected_signal: { type: "status", match: 200 } }, // bad: no id
				{ id: "INJ-VULN-09", kind: "bogus", expected_signal: { type: "status", match: 200 } }, // bad: kind
			]),
		);
		const pocs = readPocFiles(dir, logger);
		expect(pocs).toHaveLength(1);
		expect(pocs[0]?.id).toBe("INJ-VULN-01");
	});

	it("ignores a deliverables dir with no PoC sidecars", () => {
		expect(readPocFiles(path.join(os.tmpdir(), "does-not-exist-shor"), logger)).toEqual([]);
	});
});

// Exhaustiveness guard so a new ExecOutcome shape forces a test review.
const _sample: ExecOutcome = { observed: true, status: 200 };
void _sample;
