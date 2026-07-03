// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import {
	checkComposability,
	confirmChain,
	deriveDataflowEdges,
	findComposingEdge,
} from "./composability.js";
import type { OobInteraction, OobListener } from "../oracle/replay/oob/index.js";
import type { TaintObservation } from "../taint/types.js";
import type { CandidateChain, Primitive } from "./types.js";

const WRITE_LOC = { file: "post.ts", line: 10, code: "db.insert(bio)", method: "createPost" };
const RENDER_LOC = { file: "render.ts", line: 88, code: "res.send(bio)", method: "renderPost" };

const producer: Primitive = {
	id: "w",
	privilege: "low_priv",
	sideEffect: "state_write",
	vulnClass: "stored_xss",
	summary: "persist bio",
	store: "posts",
	sink: WRITE_LOC,
};
const consumer: Primitive = {
	id: "r",
	privilege: "admin",
	sideEffect: "render",
	vulnClass: "stored_xss",
	summary: "render bio",
	store: "posts",
	sink: RENDER_LOC,
};

const GOAL = { id: "g", name: "stored xss", impact: "critical" as const, steps: [] };
const chain: CandidateChain = { goal: GOAL, primitives: [producer, consumer] };

/** A second-order taint observation that PROVES posts-store bridges write→render. */
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

describe("deriveDataflowEdges", () => {
	it("extracts an edge from a second-order observation keyed by store", () => {
		const [edge] = deriveDataflowEdges([storedObs]);
		expect(edge?.store).toBe("posts");
		expect(edge?.to).toEqual(RENDER_LOC);
		expect(edge?.observationId).toBe("obs1");
	});
	it("ignores direct (single-hop) flows — they are not chain bridges", () => {
		const direct: TaintObservation = { ...storedObs, id: "d", flowKind: "direct", throughStore: undefined };
		expect(deriveDataflowEdges([direct])).toEqual([]);
	});
});

describe("checkComposability", () => {
	it("declares a chain composable when a real dataflow edge connects the pair", () => {
		const edges = deriveDataflowEdges([storedObs]);
		const result = checkComposability(chain, edges);
		expect(result.composable).toBe(true);
		expect(result.links[0]?.edge?.observationId).toBe("obs1");
	});

	it("does NOT declare a tag-compatible-but-not-composable pair a chain", () => {
		// Same store tags, same side-effects — Ali would call this complete. With NO
		// dataflow edge the stored value is not proven to reach the render sink.
		const result = checkComposability(chain, []);
		expect(result.composable).toBe(false);
		expect(result.links[0]?.reason).toContain("does not reach");
	});

	it("rejects a store mismatch even if an edge exists elsewhere", () => {
		const otherStore: Primitive = { ...consumer, store: "comments" };
		const result = checkComposability(
			{ goal: GOAL, primitives: [producer, otherStore] },
			deriveDataflowEdges([storedObs]),
		);
		expect(result.composable).toBe(false);
		expect(result.links[0]?.reason).toContain("store mismatch");
	});

	it("rejects an edge whose value reaches a DIFFERENT sink than the consumer", () => {
		const elsewhere: TaintObservation = {
			...storedObs,
			id: "obs2",
			sink: { file: "other.ts", line: 5, code: "log(bio)" },
		};
		const result = checkComposability(chain, deriveDataflowEdges([elsewhere]));
		expect(result.composable).toBe(false);
	});

	it("findComposingEdge returns undefined without a shared store", () => {
		const noStore: Primitive = { ...consumer, store: undefined };
		expect(findComposingEdge(producer, noStore, deriveDataflowEdges([storedObs]))).toBeUndefined();
	});
});

// --- Dynamic confirmation via the OOB oracle (006) ---------------------------

function fakeListener(over: Partial<OobListener> = {}): OobListener {
	return {
		ready: true,
		baseDomain: () => "sess1.oast.example",
		awaitCallback: async () => ({
			protocol: "dns",
			correlationId: "",
			labels: new Set<string>(),
			remoteAddress: "",
			timestamp: "",
		}) as OobInteraction,
		stop: async () => {},
		...over,
	};
}

const okOps = {
	storeTaggedPayload: async () => ({ observed: true }),
	triggerHighPriv: async () => ({ observed: true }),
};

describe("confirmChain — dynamic proof (mocked OOB)", () => {
	it("confirms when the tagged callback fires from the high-priv trigger", async () => {
		const proof = await confirmChain(chain, fakeListener(), okOps, { nonce: "deadbeefdeadbeef" });
		expect(proof.status).toBe("confirmed");
		expect(proof.callbackHost).toContain("sess1.oast.example");
	});

	it("is inconclusive (never a refutation) when no callback arrives", async () => {
		const listener = fakeListener({ awaitCallback: async () => null });
		const proof = await confirmChain(chain, listener, okOps, { nonce: "deadbeefdeadbeef" });
		expect(proof.status).toBe("inconclusive");
	});

	it("is inconclusive when the listener is not ready (fail-open)", async () => {
		const proof = await confirmChain(chain, fakeListener({ ready: false }), okOps);
		expect(proof.status).toBe("inconclusive");
	});

	it("is inconclusive when the store step does not fire (never asserts)", async () => {
		const proof = await confirmChain(chain, fakeListener(), {
			storeTaggedPayload: async () => ({ observed: false, detail: "write blocked" }),
			triggerHighPriv: async () => ({ observed: true }),
		});
		expect(proof.status).toBe("inconclusive");
		expect(proof.detail).toContain("store step failed");
	});
});
