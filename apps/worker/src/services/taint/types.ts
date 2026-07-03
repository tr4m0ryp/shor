// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Shared shapes for the Joern taint driver (spec T10, F14, R7).
 *
 * A `TaintSpec` is the LLM-inferred (or built-in default) description of what
 * counts as a taint SOURCE / SINK / SANITIZER for a repo, plus the persistence
 * `throughSteps` that let us model a DB write->read as a taint through-step — the
 * highest-value delta, because no static engine crosses the persistence boundary
 * automatically. The Joern CPG is queried with these specs and the deterministic
 * driver turns Joern's raw flows into typed `TaintObservation`s that downstream
 * correlation (016 guard-dominance, the proof oracle) consumes.
 *
 * Everything here is data only — no engine coupling — so the observations can be
 * serialized to a deliverable and joined by later phases on `id`.
 */

/** CPG frontend / source language. Drives the lower-confidence tag for JS/TS. */
export type TaintLanguage =
	| "java"
	| "javascript"
	| "typescript"
	| "python"
	| "go"
	| "c"
	| "unknown";

/**
 * Confidence of a taint observation. JS/TS is ALWAYS `tentative`: Joern's
 * `jssrc2cpg` frontend is weaker than the JVM one (F, R7) — reflection, computed
 * member access and middleware chains silently drop edges — so a JS/TS flow is a
 * lead, not proof. Java/other frontends may be `firm`.
 */
export type TaintConfidence = "firm" | "tentative";

/** Direct source->sink vs. a second-order flow bridged across DB persistence. */
export type TaintFlowKind = "direct" | "second_order";

/** One sink method plus the weakness class it implies (for CWE tagging). */
export interface SinkSpec {
	/** Joern name matcher (regex or literal) for the sink call. */
	readonly name: string;
	/** Human vuln class, e.g. "sql_injection", "xss", "command_injection". */
	readonly vulnClass: string;
	/** Optional CWE id, e.g. "CWE-89". */
	readonly cwe?: string | undefined;
}

/**
 * A persistence through-step: the pair of method families that WRITE tainted
 * data to a store and later READ it back. The driver treats the write as a taint
 * propagator and the matching read as a re-entry source, then joins the two
 * halves so a value stored in request A and rendered in request B is caught.
 */
export interface ThroughStepSpec {
	/** Logical store name the write/read pair shares, e.g. "users", "kv". */
	readonly store: string;
	/** Name matchers for the DB/cache WRITE calls (taint enters the store here). */
	readonly writeMethods: readonly string[];
	/** Name matchers for the DB/cache READ calls (taint re-enters from the store). */
	readonly readMethods: readonly string[];
}

/** The full taint specification handed to the query builder. */
export interface TaintSpec {
	readonly language: TaintLanguage;
	/** Name matchers for taint sources (request input, params, headers, body). */
	readonly sources: readonly string[];
	/** Sink matchers, each tagged with its vuln class. */
	readonly sinks: readonly SinkSpec[];
	/** Name matchers for sanitizers/validators that neutralize taint. */
	readonly sanitizers: readonly string[];
	/** Persistence write->read pairs enabling second-order detection. */
	readonly throughSteps: readonly ThroughStepSpec[];
	/** Provenance: built-in defaults vs. LLM augmentation over them. */
	readonly inferredBy: "default" | "llm";
}

/** One node along a taint path (best-effort location from the CPG). */
export interface TaintPathStep {
	readonly method?: string;
	readonly file?: string;
	readonly line?: number;
	readonly code?: string;
}

/**
 * A typed taint finding, keyed by a stable `id` so downstream phases (guard
 * dominance, the oracle, dedup) can correlate without re-parsing the CPG.
 */
export interface TaintObservation {
	/** Stable deterministic hash over (flowKind, vulnClass, source, sink, store). */
	readonly id: string;
	readonly flowKind: TaintFlowKind;
	readonly vulnClass: string;
	readonly cwe?: string | undefined;
	readonly source: TaintPathStep;
	readonly sink: TaintPathStep;
	/** Ordered path elements source->...->sink (may be empty if Joern omitted them). */
	readonly steps: readonly TaintPathStep[];
	/** For `second_order`: the store the value transited (write.store === read.store). */
	readonly throughStore?: string | undefined;
	readonly confidence: TaintConfidence;
	readonly language: TaintLanguage;
	/** Always "joern" today; reserved for a future Semgrep first-pass tag. */
	readonly engine: "joern";
}

/** A raw flow as emitted by the generated Joern script (pre-observation). */
export interface JoernFlow {
	readonly source: TaintPathStep;
	readonly sink: TaintPathStep;
	readonly path: readonly TaintPathStep[];
}

/** Direct-query result bucket: flows for one vuln class. */
export interface JoernDirectBucket {
	readonly vulnClass: string;
	readonly cwe?: string | undefined;
	readonly flows: readonly JoernFlow[];
}

/** Second-order half: flows source->store-write (to) or store-read->sink (from). */
export interface JoernStoreBucket {
	readonly store: string;
	readonly vulnClass?: string | undefined;
	readonly cwe?: string | undefined;
	readonly flows: readonly JoernFlow[];
}

/** The JSON payload the generated Joern script writes to its out-file. */
export interface JoernRawResult {
	readonly language: string;
	readonly direct: readonly JoernDirectBucket[];
	readonly toStore: readonly JoernStoreBucket[];
	readonly fromStore: readonly JoernStoreBucket[];
}

/** Reason the analysis produced no observations without failing the scan. */
export interface TaintDegradation {
	readonly reason:
		| "disabled"
		| "joern_missing"
		| "cpg_build_failed"
		| "query_failed"
		| "empty_repo";
	readonly detail: string;
}

/** Final result the service returns. `degraded` is set on any fail-open path. */
export interface TaintResult {
	readonly observations: readonly TaintObservation[];
	readonly language: TaintLanguage;
	readonly specInferredBy: "default" | "llm";
	readonly cpgPath?: string;
	readonly degraded?: TaintDegradation;
}
