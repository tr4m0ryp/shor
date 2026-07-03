// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { afterEach, describe, expect, it } from "vitest";
import {
	chainEnabled,
	evaluateChain,
	PrimitiveLedger,
	primitivesFromTaint,
	runChaining,
} from "./index.js";
import type { CandidateChain, ChainProof, Primitive } from "./types.js";
import type { TaintObservation } from "../taint/types.js";

const saved = { ...process.env };
afterEach(() => {
	process.env = { ...saved };
});

const WRITE_LOC = { file: "post.ts", line: 10, code: "db.insert(bio)" };
const RENDER_LOC = { file: "render.ts", line: 88, code: "res.send(bio)" };

const storedObs: TaintObservation = {
	id: "obs1",
	flowKind: "second_order",
	vulnClass: "stored_xss",
	source: WRITE_LOC,
	sink: RENDER_LOC,
	throughStore: "posts",
	steps: [],
	confidence: "tentative",
	language: "typescript",
	engine: "joern",
};

const confirmed: ChainProof = { status: "confirmed", detail: "callback fired", callbackHost: "x.oast" };

describe("chainEnabled — flag gate (default OFF)", () => {
	it("is OFF unless SHOR_CHAIN=1", () => {
		expect(chainEnabled({})).toBe(false);
		expect(chainEnabled({ SHOR_CHAIN: "true" })).toBe(false);
		expect(chainEnabled({ SHOR_CHAIN: "1" })).toBe(true);
	});

	it("runChaining returns nothing when the flag is off (stock scan unchanged)", async () => {
		delete process.env.SHOR_CHAIN;
		const ledger = PrimitiveLedger.create(primitivesFromTaint([storedObs]));
		expect(await runChaining(ledger)).toEqual([]);
	});
});

describe("primitivesFromTaint", () => {
	it("derives a writer + reader keyed to the same store from a stored flow", () => {
		const prims = primitivesFromTaint([storedObs]);
		expect(prims).toHaveLength(2);
		const writer = prims.find((p) => p.sideEffect === "state_write");
		const reader = prims.find((p) => p.sideEffect === "render");
		expect(writer?.store).toBe("posts");
		expect(reader?.store).toBe("posts");
		expect(reader?.sink).toEqual(RENDER_LOC);
		expect(writer?.privilege).toBe("low_priv");
		expect(reader?.privilege).toBe("high_priv");
	});
});

describe("evaluateChain", () => {
	const producer: Primitive = {
		id: "w",
		privilege: "low_priv",
		sideEffect: "state_write",
		vulnClass: "stored_xss",
		summary: "w",
		store: "posts",
		sink: WRITE_LOC,
	};
	const consumer: Primitive = {
		id: "r",
		privilege: "admin",
		sideEffect: "render",
		vulnClass: "stored_xss",
		summary: "r",
		store: "posts",
		sink: RENDER_LOC,
	};
	const chain: CandidateChain = {
		goal: { id: "g", name: "g", impact: "critical", steps: [] },
		primitives: [producer, consumer],
	};

	it("returns unproven when no dataflow edge composes the chain (tags alone)", async () => {
		const v = await evaluateChain(chain, { observations: [] });
		expect(v.status).toBe("unproven");
	});

	it("returns composable when edges connect it but no dynamic hook runs", async () => {
		const v = await evaluateChain(chain, { observations: [storedObs] });
		expect(v.status).toBe("composable");
	});

	it("returns confirmed for a composable chain proven by (mocked) dynamic proof", async () => {
		const v = await evaluateChain(chain, {
			observations: [storedObs],
			confirm: async () => confirmed,
		});
		expect(v.status).toBe("confirmed");
		expect(v.dynamic?.status).toBe("confirmed");
	});
});

describe("runChaining — end to end", () => {
	it("confirms a real composable stored-XSS chain via dynamic proof", async () => {
		const ledger = PrimitiveLedger.create(primitivesFromTaint([storedObs]));
		const verdicts = await runChaining(ledger, {
			enabled: true,
			observations: [storedObs],
			confirm: async () => confirmed,
		});
		const xss = verdicts.find((v) => v.goal.id === "stored_xss_to_privileged_session");
		expect(xss?.status).toBe("confirmed");
	});

	it("marks a tag-complete but non-composable chain UNPROVEN, never complete", async () => {
		// Same tags fill the stored-XSS goal, but the writer and reader touch
		// DIFFERENT stores -> no dataflow edge -> unproven (Ali would call it done).
		const writer: Primitive = {
			id: "w",
			privilege: "low_priv",
			sideEffect: "state_write",
			vulnClass: "stored_xss",
			summary: "w",
			store: "posts",
			sink: WRITE_LOC,
		};
		const reader: Primitive = {
			id: "r",
			privilege: "high_priv",
			sideEffect: "render",
			vulnClass: "stored_xss",
			summary: "r",
			store: "comments",
			sink: RENDER_LOC,
		};
		const ledger = PrimitiveLedger.create([writer, reader]);
		const verdicts = await runChaining(ledger, { enabled: true, confirm: async () => confirmed });
		const xss = verdicts.find((v) => v.goal.id === "stored_xss_to_privileged_session");
		expect(xss?.status).toBe("unproven");
	});
});
