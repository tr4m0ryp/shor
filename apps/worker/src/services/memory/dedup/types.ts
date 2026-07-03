// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Cross-scan dedup / novelty types (spec T6, R10).
 *
 * The cross-scan extension of the shipped per-scan `services/dedup-judge`:
 * a deterministic `fpv1` fingerprint fast-path, then embedding recall +
 * complete-linkage clustering + a structural gate, then grey-band LLM
 * adjudication. Everything here is a plain shape so the logic modules stay pure
 * and unit-testable; the DB repositories (apps/web) are reached through injected
 * ports (mirroring `../write/persist.ts`), never imported across the package
 * boundary.
 */

import type { FindingLike } from "../schema/index.js";

/** A dense embedding — the pgvector repos expect a 1024-dim number array. */
export type Vector = readonly number[];

/**
 * Novelty of a finding relative to memory:
 *   - `novel`        — a new root cause not seen before.
 *   - `rediscovered` — matched a prior finding already in the memory tier.
 *   - `known`        — matched public known-vuln data (OSV/GHSA/NVD, see enrich).
 */
export type NoveltyLabel = "novel" | "rediscovered" | "known";

/** How a candidate matched an existing item (for the audit trail). */
export type MatchKind = "fingerprint" | "cluster" | "adjudicated" | "none";

/**
 * The structural axes the gate must AGREE on before two findings may merge
 * (spec T6: "must agree on file / CWE / endpoint / component"). A shared
 * anchor on any of these axes admits a merge; no shared anchor blocks it — so
 * an SSRF in one file never folds into an XSS in another.
 */
export interface StructuralKey {
	readonly fileBase: string | null;
	readonly cwe: string | null;
	readonly cweFamily: string | null;
	readonly endpoint: string | null;
	readonly component: string | null;
	readonly category: string | null;
}

/**
 * A prior finding pulled from the local memory tier for cross-scan comparison.
 * `distance` is the pgvector cosine distance from the ANN recall query (absent
 * on a fingerprint-only prior); `structural` drives the gate.
 */
export interface PriorFinding {
	readonly id: string;
	readonly fpv1?: string | null;
	readonly clusterId?: string | null;
	readonly distance?: number | null;
	readonly structural: StructuralKey;
}

/** A candidate finding paired with the vector used for its embedding recall. */
export interface DedupCandidate {
	readonly finding: FindingLike;
	/** Text-space embedding (Vector A) for ANN recall; null skips recall. */
	readonly vecText?: Vector | null;
}

/** Per-candidate cross-scan dedup verdict (never drops the finding). */
export interface DedupVerdict {
	readonly findingId: string;
	readonly fpv1: string;
	readonly novelty: NoveltyLabel;
	/** Stable cluster id the finding belongs to after dedup. */
	readonly clusterId: string;
	/** Memory id (prior finding) the candidate merged into, when any. */
	readonly mergedInto?: string;
	/** Ids of same-scan siblings folded into this cluster (recall-safe). */
	readonly alsoReportedAs: readonly string[];
	readonly matchKind: MatchKind;
	/** Best similarity to the merged item, when a semantic match drove it. */
	readonly similarity?: number;
	readonly reason: string;
}

/** A calibrated similarity threshold + grey band (from a sweep, not a constant). */
export interface CalibratedThreshold {
	/** The decision boundary similarity swept from the labeled set. */
	readonly threshold: number;
	/** Below this similarity -> confidently distinct. */
	readonly greyLow: number;
	/** At/above this similarity (+ structural gate) -> confident merge. */
	readonly greyHigh: number;
	readonly f1: number;
	readonly precision: number;
	readonly recall: number;
	/** How the sweep was scored (beta<1 biases to precision). */
	readonly beta: number;
}

/**
 * Grey-band adjudicator port: decides whether two findings share a root cause
 * when their similarity sits inside the grey band. MUST never throw (fail
 * open to "distinct" so a flaky judge can never merge a real new bug away).
 */
export type AdjudicateFn = (
	a: FindingLike,
	b: FindingLike,
) => Promise<boolean>;

/** Cross-scan recall port: nearest prior findings for a candidate vector. */
export type RecallFn = (
	candidate: DedupCandidate,
) => Promise<readonly PriorFinding[]>;
