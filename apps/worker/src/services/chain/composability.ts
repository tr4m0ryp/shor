// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Composability — the piece that kills Ali's fatal gap (spec T11, F8).
 *
 * Ali declares a chain complete when the ledger has a type-tag match for every
 * step, so causally-UNRELATED primitives are reported as a working exploit chain.
 * We refuse to: two adjacent primitives compose ONLY when a REAL dataflow edge
 * connects them — the value the producer stores must actually reach the sink the
 * consumer fires (derived from a task-015 second-order taint observation, or an
 * explicit edge). No edge ⇒ the pair does not compose ⇒ the chain is `unproven`;
 * we NEVER assert on tags alone.
 *
 * `confirmChain` is the DYNAMIC half: mint a request-bound OOB token (006), have
 * the caller store a payload tagged with it as low-priv and trigger the render as
 * high-priv, and treat a witnessed callback as proof the stored value executed in
 * the privileged session. Blind-class fail-open: no callback ⇒ inconclusive,
 * never a refutation.
 */

import { mintToken } from "../oracle/replay/oob/index.js";
import type { AwaitOptions, OobListener } from "../oracle/replay/oob/index.js";
import type { TaintObservation, TaintPathStep } from "../taint/types.js";
import type {
	CandidateChain,
	ChainProof,
	CompositionLink,
	CompositionResult,
	DataflowEdge,
	Primitive,
} from "./types.js";

/**
 * Extract candidate dataflow edges from taint observations. A `second_order`
 * observation IS a proven persistence bridge (input → store → sink), so it
 * supplies the exact edge composability needs: `from` = where the value was
 * stored, `to` = the sink the stored value reaches, keyed by the shared store.
 */
export function deriveDataflowEdges(
	observations: readonly TaintObservation[],
): DataflowEdge[] {
	const edges: DataflowEdge[] = [];
	for (const o of observations) {
		if (o.flowKind !== "second_order" || !o.throughStore) continue;
		edges.push({ observationId: o.id, store: o.throughStore, from: o.source, to: o.sink });
	}
	return edges;
}

/** Do two CPG locations refer to the same place? File+line when present, else code. */
function locMatches(a: TaintPathStep, b: TaintPathStep): boolean {
	if (a.file && b.file) {
		if (a.file !== b.file) return false;
		if (a.line != null && b.line != null) return a.line === b.line;
		return true;
	}
	if (a.code && b.code) return a.code === b.code;
	return false;
}

/**
 * Find the dataflow edge that composes `producer`→`consumer`, or undefined.
 * Requires: a shared persistence store (producer wrote it, consumer reads it) AND
 * the edge's endpoint actually reaching the consumer's sink — i.e. the stored
 * value truly reaches the render/trigger point, not merely sharing a tag.
 */
export function findComposingEdge(
	producer: Primitive,
	consumer: Primitive,
	edges: readonly DataflowEdge[],
): DataflowEdge | undefined {
	const store = producer.store;
	if (!store || consumer.store !== store) return undefined;
	if (!consumer.sink) return undefined;
	return edges.find(
		(e) => e.store === store && consumer.sink !== undefined && locMatches(e.to, consumer.sink),
	);
}

/** Human, non-secret reason a pair failed to compose. */
function noEdgeReason(producer: Primitive, consumer: Primitive): string {
	if (!producer.store || !consumer.store) {
		return `no shared store between ${producer.id} and ${consumer.id}`;
	}
	if (producer.store !== consumer.store) {
		return `store mismatch (${producer.store} vs ${consumer.store}) between ${producer.id} and ${consumer.id}`;
	}
	return `no dataflow edge: stored value does not reach ${consumer.id}'s sink`;
}

/**
 * Static composability over a whole chain: walk each adjacent primitive pair and
 * require a real dataflow edge. `composable` is true ONLY when every pair composes.
 */
export function checkComposability(
	chain: CandidateChain,
	edges: readonly DataflowEdge[],
): CompositionResult {
	const links: CompositionLink[] = [];
	const prims = chain.primitives;
	for (let i = 0; i + 1 < prims.length; i++) {
		const from = prims[i] as Primitive;
		const to = prims[i + 1] as Primitive;
		const edge = findComposingEdge(from, to, edges);
		links.push(
			edge
				? { from, to, composable: true, edge }
				: { from, to, composable: false, reason: noEdgeReason(from, to) },
		);
	}
	// A single-primitive "chain" is not a chain; require ≥1 composed link.
	const composable = links.length > 0 && links.every((l) => l.composable);
	return { links, composable };
}

/**
 * Injected side-effecting ops for the dynamic confirmation. The live wiring (008)
 * binds these to the replay executors + identities: `storeTaggedPayload` fires the
 * producer's write AS the low-priv attacker with the OOB host embedded; the render
 * runs in the high-priv session. Modeled as injected ops so the sequence is
 * unit-testable and the mutating write lands behind 008's gate.
 */
export interface ChainProofOps {
	/** Store a payload tagged with `callbackHost` as the low-priv attacker. */
	storeTaggedPayload(callbackHost: string): Promise<{ observed: boolean; detail?: string }>;
	/** Trigger the high-priv render/read that should cause the target to call back. */
	triggerHighPriv(): Promise<{ observed: boolean; detail?: string }>;
}

export interface ConfirmChainOptions {
	/** Injectable nonce for deterministic tests. */
	readonly nonce?: string;
	/** Forwarded to `listener.awaitCallback`. */
	readonly await?: AwaitOptions;
}

/** Deterministic witness seed binding a token to THIS chain (goal + primitive ids). */
function witnessSeed(chain: CandidateChain): string {
	return `${chain.goal.id}\n${chain.primitives.map((p) => p.id).join(",")}`;
}

function inconclusive(detail: string, callbackHost?: string): ChainProof {
	return { status: "inconclusive", detail, ...(callbackHost !== undefined && { callbackHost }) };
}

/**
 * Dynamically confirm a composable chain via the OOB oracle (006): store the
 * tagged payload as low-priv, trigger the render as high-priv, and await a
 * witnessed callback. A callback ⇒ the stored value executed in the privileged
 * session (`confirmed`). Anything else (no listener, a failed step, no callback)
 * ⇒ `inconclusive` — NEVER a refutation (blind-class fail-open, mirrors the OOB
 * executor). Never throws.
 */
export async function confirmChain(
	chain: CandidateChain,
	listener: OobListener | undefined,
	ops: ChainProofOps,
	opts: ConfirmChainOptions = {},
): Promise<ChainProof> {
	if (!listener?.ready) return inconclusive("interactsh listener not available");
	const base = listener.baseDomain();
	if (!base) return inconclusive("no interactsh base domain");

	const token = mintToken(base, witnessSeed(chain), opts.nonce);
	let stored: { observed: boolean; detail?: string };
	try {
		stored = await ops.storeTaggedPayload(token.callbackHost);
	} catch (err) {
		return inconclusive(`store step threw: ${err instanceof Error ? err.message : String(err)}`, token.callbackHost);
	}
	if (!stored.observed) return inconclusive(`store step failed: ${stored.detail ?? "not observed"}`, token.callbackHost);

	let triggered: { observed: boolean; detail?: string };
	try {
		triggered = await ops.triggerHighPriv();
	} catch (err) {
		return inconclusive(`trigger step threw: ${err instanceof Error ? err.message : String(err)}`, token.callbackHost);
	}
	if (!triggered.observed) return inconclusive(`trigger step failed: ${triggered.detail ?? "not observed"}`, token.callbackHost);

	const hit = await listener.awaitCallback(token, opts.await);
	if (hit) {
		return {
			status: "confirmed",
			detail: "tagged OOB callback fired from the high-priv trigger (stored value executed cross-privilege)",
			callbackHost: token.callbackHost,
		};
	}
	return inconclusive("no witnessed OOB callback within window", token.callbackHost);
}
