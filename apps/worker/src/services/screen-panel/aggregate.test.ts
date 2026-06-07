// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import { buildVerdictEntry, decideVotes } from "./aggregate.js";
import {
	DEFAULT_VOTERS,
	LENSES,
	lensesForCategory,
	MAX_VOTERS,
	panelSizeForCategory,
	REACHABILITY_LENS,
	resolvePanelSize,
	VOTERS_ENV,
} from "./lenses.js";
import { createSessionPool, SCREEN_SESSIONS } from "./session-pool.js";
import type { ScreenDecision, ScreenVote } from "./types.js";

/** Build a ballot list from `[lens, verdict]` pairs (voter ordinal = index+1). */
function votes(...pairs: [string, ScreenDecision][]): ScreenVote[] {
	return pairs.map(([lens, verdict], i) => ({
		voter: i + 1,
		lens,
		verdict,
		reason: `${lens}:${verdict}`,
	}));
}

describe("decideVotes — majority aggregation", () => {
	it("3 votes with a refute majority decides refute", () => {
		const decision = decideVotes(
			votes(
				["control-sanitizer", "refute"],
				["exploitability", "refute"],
				["control-sanitizer", "support"],
			),
		);
		expect(decision).toBe("refute");
	});

	it("3 votes with a support majority decides support", () => {
		const decision = decideVotes(
			votes(
				["control-sanitizer", "support"],
				["exploitability", "support"],
				["control-sanitizer", "refute"],
			),
		);
		expect(decision).toBe("support");
	});

	it("unanimous votes decide that verdict", () => {
		expect(
			decideVotes(
				votes(
					["control-sanitizer", "refute"],
					["exploitability", "refute"],
					["control-sanitizer", "refute"],
				),
			),
		).toBe("refute");
	});

	it("an empty ballot is uncertain (fail open)", () => {
		expect(decideVotes([])).toBe("uncertain");
	});
});

describe("decideVotes — ties and splits collapse to uncertain", () => {
	it("an even refute/support split is uncertain", () => {
		expect(
			decideVotes(
				votes(["control-sanitizer", "refute"], ["exploitability", "support"]),
			),
		).toBe("uncertain");
	});

	it("a three-way split (refute/support/uncertain) is uncertain", () => {
		expect(
			decideVotes(
				votes(
					["control-sanitizer", "refute"],
					["exploitability", "support"],
					["control-sanitizer", "uncertain"],
				),
			),
		).toBe("uncertain");
	});

	it("a plurality that is not strict (2/2/1) is uncertain", () => {
		expect(
			decideVotes(
				votes(
					["control-sanitizer", "refute"],
					["exploitability", "refute"],
					["control-sanitizer", "support"],
					["exploitability", "support"],
					["control-sanitizer", "uncertain"],
				),
			),
		).toBe("uncertain");
	});
});

describe("decideVotes — reachability veto", () => {
	it("a reachability refute downgrades a support majority to uncertain", () => {
		const decision = decideVotes(
			votes(
				["exploitability", "support"],
				["control-sanitizer", "support"],
				[REACHABILITY_LENS, "refute"],
			),
		);
		// Majority would be support, but the reachability lens vetoes it.
		expect(decision).toBe("uncertain");
	});

	it("a reachability support does NOT veto a support majority", () => {
		expect(
			decideVotes(
				votes(
					["exploitability", "support"],
					["control-sanitizer", "support"],
					[REACHABILITY_LENS, "support"],
				),
			),
		).toBe("support");
	});

	it("a non-reachability refute does NOT veto a support majority", () => {
		expect(
			decideVotes(
				votes(
					["exploitability", "support"],
					["control-sanitizer", "support"],
					["exploitability", "refute"],
				),
			),
		).toBe("support");
	});

	it("the veto never flips a refute majority (only blocks support)", () => {
		expect(
			decideVotes(
				votes(
					[REACHABILITY_LENS, "refute"],
					["control-sanitizer", "refute"],
					["exploitability", "support"],
				),
			),
		).toBe("refute");
	});
});

describe("buildVerdictEntry", () => {
	it("orders ballots by voter and stamps the aggregated decision", () => {
		const entry = buildVerdictEntry("INJECTION-VULN-01", [
			{ voter: 3, lens: "exploitability", verdict: "support", reason: "" },
			{ voter: 1, lens: "reachability", verdict: "refute", reason: "" },
			{ voter: 2, lens: "control-sanitizer", verdict: "refute", reason: "" },
		]);
		expect(entry.id).toBe("INJECTION-VULN-01");
		expect(entry.votes.map((v) => v.voter)).toEqual([1, 2, 3]);
		expect(entry.decision).toBe("refute");
	});
});

describe("panel size N is configurable", () => {
	it("defaults to DEFAULT_VOTERS when the env var is unset/blank", () => {
		expect(resolvePanelSize({})).toBe(DEFAULT_VOTERS);
		expect(resolvePanelSize({ [VOTERS_ENV]: "" })).toBe(DEFAULT_VOTERS);
		expect(resolvePanelSize({ [VOTERS_ENV]: "not-a-number" })).toBe(
			DEFAULT_VOTERS,
		);
	});

	it("honors a valid override and clamps to [1, MAX_VOTERS]", () => {
		expect(resolvePanelSize({ [VOTERS_ENV]: "5" })).toBe(5);
		expect(resolvePanelSize({ [VOTERS_ENV]: "1" })).toBe(1);
		expect(resolvePanelSize({ [VOTERS_ENV]: "99" })).toBe(MAX_VOTERS);
		expect(resolvePanelSize({ [VOTERS_ENV]: "0" })).toBe(DEFAULT_VOTERS);
	});
});

describe("lensesForCategory", () => {
	it("returns exactly N lenses, distinct for the base triad at N=3", () => {
		const lenses = lensesForCategory("injection", 3);
		expect(lenses).toEqual([
			"reachability",
			"control-sanitizer",
			"exploitability",
		]);
		expect(new Set(lenses).size).toBe(3);
	});

	it("gives authz a fourth auth-context lens", () => {
		expect(lensesForCategory("authz", 4)).toEqual([
			"reachability",
			"control-sanitizer",
			"exploitability",
			"auth-context",
		]);
		expect(LENSES.authz).toContain("auth-context");
	});

	it("cycles the pool when N exceeds it", () => {
		const lenses = lensesForCategory("injection", 5);
		expect(lenses).toHaveLength(5);
		expect(lenses[3]).toBe("reachability");
		expect(lenses[4]).toBe("control-sanitizer");
	});

	it("falls back to the base triad for an unknown category", () => {
		expect(lensesForCategory("totally-unknown", 3)).toEqual([
			"reachability",
			"control-sanitizer",
			"exploitability",
		]);
	});
});

describe("panelSizeForCategory", () => {
	it("gives authz a 4th voter so its auth-context lens actually runs", () => {
		// Default panel size is 3; authz has a 4-lens pool → it must get 4.
		expect(panelSizeForCategory("authz", {})).toBe(4);
		const lenses = lensesForCategory("authz", panelSizeForCategory("authz", {}));
		expect(lenses).toContain("auth-context");
	});

	it("leaves 3-lens categories at the default size", () => {
		expect(panelSizeForCategory("injection", {})).toBe(DEFAULT_VOTERS);
		expect(panelSizeForCategory("xss", {})).toBe(DEFAULT_VOTERS);
	});

	it("honors a larger configured panel size, capped at MAX_VOTERS", () => {
		expect(panelSizeForCategory("injection", { [VOTERS_ENV]: "5" })).toBe(5);
		expect(panelSizeForCategory("authz", { [VOTERS_ENV]: "99" })).toBe(MAX_VOTERS);
	});
});

describe("createSessionPool", () => {
	it("hands out distinct sessions up to its size, never sharing one", async () => {
		const pool = createSessionPool(SCREEN_SESSIONS);
		const leases = await Promise.all(
			SCREEN_SESSIONS.map(() => pool.acquire()),
		);
		const held = leases.map((l) => l.session);
		expect(new Set(held).size).toBe(SCREEN_SESSIONS.length);
		expect(pool.size).toBe(SCREEN_SESSIONS.length);
	});

	it("blocks acquire when full and resolves it as soon as a lease releases", async () => {
		const pool = createSessionPool(["agent1", "agent2"]);
		const a = await pool.acquire();
		const b = await pool.acquire();

		let thirdResolved = false;
		const third = pool.acquire().then((lease) => {
			thirdResolved = true;
			return lease;
		});
		// Pool is full (2/2); the third acquire must stay pending.
		await Promise.resolve();
		expect(thirdResolved).toBe(false);

		// Releasing one hands its session straight to the waiter.
		b.release();
		const recycled = await third;
		expect(thirdResolved).toBe(true);
		expect(recycled.session).toBe(b.session);

		a.release();
		recycled.release();
	});

	it("ignores a double release so a finally can call it unconditionally", async () => {
		const pool = createSessionPool(["agent1"]);
		const first = await pool.acquire();
		first.release();
		first.release(); // no-op — must not free a second phantom slot

		// Exactly one slot exists, and it is free again: a fresh acquire resolves.
		const reacquired = await pool.acquire();
		expect(reacquired.session).toBe("agent1");

		// A second concurrent acquire must block (the double release added no slot).
		let extraResolved = false;
		void pool.acquire().then(() => {
			extraResolved = true;
		});
		await Promise.resolve();
		expect(extraResolved).toBe(false);
	});
});
