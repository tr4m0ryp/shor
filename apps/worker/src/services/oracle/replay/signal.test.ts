// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Pure-logic tests for the oracle: signal matching across all four signal types,
 * the read-only safety gate, and the outcome → verdict reducer.
 */

import { describe, expect, it } from "vitest";
import { decide, isReadOnly, matchSignal } from "./signal.js";
import type { ExecOutcome, ExpectedSignal, Poc } from "./types.js";

function httpPoc(over: Partial<Poc> = {}): Poc {
	return {
		id: "INJ-VULN-01",
		kind: "http",
		request: { method: "GET", url: "https://t.example/x" },
		expected_signal: { type: "status", match: 200 },
		...over,
	};
}

const observed = (o: Partial<Extract<ExecOutcome, { observed: true }>>): ExecOutcome => ({
	observed: true,
	...o,
});

describe("matchSignal", () => {
	it("status: matches on equal code (number or string), rejects otherwise", () => {
		const sig: ExpectedSignal = { type: "status", match: 200 };
		expect(matchSignal(sig, observed({ status: 200 }))).toBe(true);
		expect(matchSignal({ type: "status", match: "200" }, observed({ status: 200 }))).toBe(true);
		expect(matchSignal(sig, observed({ status: 403 }))).toBe(false);
		expect(matchSignal(sig, observed({}))).toBe(false);
	});

	it("reflection: matches when the payload is echoed in the body", () => {
		const sig: ExpectedSignal = { type: "reflection", match: "<svg/onload=alert(1)>" };
		expect(matchSignal(sig, observed({ body: "ok <svg/onload=alert(1)> done" }))).toBe(true);
		expect(matchSignal(sig, observed({ body: "encoded &lt;svg/onload..." }))).toBe(false);
	});

	it("data: matches when the sensitive-data marker appears in the body", () => {
		const sig: ExpectedSignal = { type: "data", match: "root:x:0:0" };
		expect(matchSignal(sig, observed({ body: "root:x:0:0:/root" }))).toBe(true);
		expect(matchSignal(sig, observed({ body: "permission denied" }))).toBe(false);
	});

	it("oob: matches only when an out-of-band callback was observed", () => {
		const sig: ExpectedSignal = { type: "oob", match: "abc123.oast.site" };
		expect(matchSignal(sig, observed({ oobObserved: true }))).toBe(true);
		expect(matchSignal(sig, observed({ oobObserved: false }))).toBe(false);
	});

	it("never matches a non-observed outcome", () => {
		expect(matchSignal({ type: "status", match: 200 }, { observed: false, reason: "error" })).toBe(false);
	});
});

describe("isReadOnly (safety gate)", () => {
	// PoCs that carry no `request` (gate must default the method to GET).
	const noRequest = (kind: Poc["kind"]): Poc => ({
		id: "INJ-VULN-01",
		kind,
		expected_signal: { type: "status", match: 200 },
	});

	it("allows idempotent GET / HEAD", () => {
		expect(isReadOnly(httpPoc({ request: { method: "GET", url: "https://t/x" } }))).toBe(true);
		expect(isReadOnly(httpPoc({ request: { method: "head", url: "https://t/x" } }))).toBe(true);
		expect(isReadOnly(noRequest("http"))).toBe(true); // defaults to GET
	});

	it("rejects state-changing methods unless explicitly vouched safe", () => {
		expect(isReadOnly(httpPoc({ request: { method: "POST", url: "https://t/x" } }))).toBe(false);
		expect(isReadOnly(httpPoc({ request: { method: "DELETE", url: "https://t/x" } }))).toBe(false);
		expect(isReadOnly(httpPoc({ request: { method: "POST", url: "https://t/x" }, safe: true }))).toBe(true);
	});

	it("only replays browser / oob PoCs when explicitly vouched safe", () => {
		expect(isReadOnly(noRequest("browser"))).toBe(false);
		expect(isReadOnly(noRequest("oob"))).toBe(false);
		expect(isReadOnly({ ...noRequest("oob"), safe: true })).toBe(true);
	});
});

describe("decide", () => {
	it("observed + matching signal → exploited", () => {
		const v = decide(httpPoc(), observed({ status: 200 }));
		expect(v.disposition).toBe("exploited");
		expect(v.rateLimited).toBe(false);
	});

	it("observed + absent signal → blocked", () => {
		const v = decide(httpPoc(), observed({ status: 403 }));
		expect(v.disposition).toBe("blocked");
	});

	it("rate-limited → not_replayable + backoff flag", () => {
		const v = decide(httpPoc(), { observed: false, reason: "rate_limited" });
		expect(v.disposition).toBe("not_replayable");
		expect(v.rateLimited).toBe(true);
	});

	it("transport error / unwired → not_replayable (no backoff)", () => {
		expect(decide(httpPoc(), { observed: false, reason: "error", detail: "ECONNREFUSED" }).disposition).toBe(
			"not_replayable",
		);
		expect(decide(httpPoc(), { observed: false, reason: "not_replayable" }).disposition).toBe("not_replayable");
	});
});
