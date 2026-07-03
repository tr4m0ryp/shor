// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * services/taint — Joern CPG interprocedural taint driver (spec T10, F14, R7).
 *
 * Public surface only. Joern (Apache-2.0) is the sole engine — CodeQL is NEVER
 * embedded (its license forbids private-code + automated-service use). The
 * headline capability is the DB write->read THROUGH-STEP that catches second-
 * order/stored flows no static engine models automatically. Everything is
 * flag-gated (`SHOR_TAINT`) and fail-open, so a stock scan is unchanged.
 *
 * Consumers (016 guard-dominance, the proof oracle) read `TaintObservation`s and
 * correlate on their stable `id`. The CPG built here is reusable by 016.
 */

export { runTaintAnalysis, resolveJoernBins, taintEnabled } from "./joern/driver.js";
export type { RunTaintOptions } from "./joern/driver.js";
export { buildTaintScript, joernLanguageFlag, groupSinks } from "./joern/queries.js";
export {
	parseObservations,
	secondOrderObservations,
	toTaintLanguage,
} from "./joern/parse.js";
export {
	confidenceForLanguage,
	defaultSpec,
	detectLanguageFromFiles,
	languageForPath,
} from "./specs/defaults.js";
export { inferSpec, mergeSpec, specInferenceEnabled } from "./specs/infer.js";
export type { InferSpecOptions, InferSpecResult } from "./specs/infer.js";
export type {
	JoernFlow,
	JoernRawResult,
	SinkSpec,
	TaintConfidence,
	TaintDegradation,
	TaintFlowKind,
	TaintLanguage,
	TaintObservation,
	TaintPathStep,
	TaintResult,
	TaintSpec,
	ThroughStepSpec,
} from "./types.js";
