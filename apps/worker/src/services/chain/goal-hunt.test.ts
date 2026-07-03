// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import {
	DEFAULT_GOALS,
	huntGoal,
	huntGoals,
	nextHunt,
	toCandidateChain,
} from "./goal-hunt.js";
import { PrimitiveLedger } from "./ledger.js";
import type { Goal, Primitive } from "./types.js";

const XSS_GOAL: Goal = DEFAULT_GOALS.find((g) => g.id === "stored_xss_to_privileged_session")!;

function prim(over: Partial<Primitive> & Pick<Primitive, "id">): Primitive {
	return {
		privilege: "low_priv",
		sideEffect: "state_write",
		vulnClass: "stored_xss",
		summary: "test",
		...over,
	};
}

const writer = prim({ id: "w", privilege: "low_priv", sideEffect: "state_write" });
const render = prim({ id: "r", privilege: "admin", sideEffect: "render" });

describe("huntGoal", () => {
	it("matches steps by side-effect and privilege band", () => {
		const ledger = PrimitiveLedger.create([writer, render]);
		const m = huntGoal(XSS_GOAL, ledger);
		expect(m.complete).toBe(true);
		expect(m.matchedCount).toBe(2);
		expect(m.missingCount).toBe(0);
		expect(m.matches.map((s) => s.primitive?.id)).toEqual(["w", "r"]);
	});

	it("rejects a primitive OUTSIDE the step's privilege band", () => {
		// A render primitive at low_priv cannot fill the "privileged victim" step
		// (band high_priv..admin) — so the goal is one primitive away, not complete.
		const lowRender = prim({ id: "lr", privilege: "low_priv", sideEffect: "render" });
		const ledger = PrimitiveLedger.create([writer, lowRender]);
		const m = huntGoal(XSS_GOAL, ledger);
		expect(m.complete).toBe(false);
		expect(m.missingCount).toBe(1);
	});

	it("never claims the same primitive for two steps", () => {
		const ledger = PrimitiveLedger.create([writer]); // only a writer
		const m = huntGoal(XSS_GOAL, ledger);
		expect(m.matchedCount).toBe(1);
		expect(m.matches[1]?.primitive).toBeUndefined();
	});
});

describe("huntGoals — proximity ranking", () => {
	it("floats a 'one primitive away' goal above a further one", () => {
		// Ledger completes nothing but gets the XSS goal to 1-away (has a writer),
		// while the IDOR goal has 0 of its steps -> XSS ranks first (fewer missing).
		const ledger = PrimitiveLedger.create([writer]);
		const ranked = huntGoals(DEFAULT_GOALS, ledger);
		expect(ranked[0]?.missingCount).toBeLessThanOrEqual(ranked[1]?.missingCount ?? Infinity);
		// The stored-write goals (xss, ssrf) are 1-away; idor (needs a cross_user
		// write) is 2-away and must not lead.
		expect(ranked[0]?.goal.id).not.toBe("idor_write_to_auth_takeover");
	});
});

describe("nextHunt", () => {
	it("directs the hunt at the closest incomplete goal's first gap", () => {
		const ledger = PrimitiveLedger.create([writer]); // XSS goal is 1-away (render missing)
		const directive = nextHunt(huntGoals(DEFAULT_GOALS, ledger));
		expect(directive?.missingStep.sideEffect).toBeDefined();
		expect(directive?.missingCount).toBeGreaterThan(0);
	});

	it("returns undefined when every goal is complete or unmatchable", () => {
		const complete = huntGoal(XSS_GOAL, PrimitiveLedger.create([writer, render]));
		expect(nextHunt([complete])).toBeUndefined();
	});
});

describe("toCandidateChain", () => {
	it("builds an ordered chain from a complete match", () => {
		const m = huntGoal(XSS_GOAL, PrimitiveLedger.create([writer, render]));
		const chain = toCandidateChain(m);
		expect(chain?.primitives.map((p) => p.id)).toEqual(["w", "r"]);
	});
	it("returns undefined for an incomplete match", () => {
		const m = huntGoal(XSS_GOAL, PrimitiveLedger.create([writer]));
		expect(toCandidateChain(m)).toBeUndefined();
	});
});
