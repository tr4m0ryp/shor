// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Contract for the mandatory secret/PII scrub stage (spec T2 guardrails, R4).
 *
 * scrub() is the pre-ingest filter every memory write MUST pass through:
 * secrets are quarantined (never emitted downstream), PII is redacted before
 * text is embedded (embeddings are invertible — F12/R4), and any engine
 * failure fails CLOSED: no clean output, the caller must not store.
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";

/** Which engine produced a secret hit. `injected` = caller/test-supplied detector. */
export type SecretSource = "gitleaks" | "trufflehog" | "injected";

/** Absolute `[start, end)` character span in the scanned text. */
export interface TextSpan {
	start: number;
	end: number;
}

/**
 * One raw detector hit. Exactly one locator is set:
 * - `value` — the raw secret string (trufflehog-style). Held transiently in
 *   process memory only long enough to excise it; NEVER logged, persisted, or
 *   emitted downstream in any form.
 * - `span`  — `[start, end)` offsets into the scanned text (gitleaks-style,
 *   derived from a `--redact`ed report, so the raw value never even enters
 *   this process via that path).
 */
export interface SecretHit {
	source: SecretSource;
	ruleId: string;
	value?: string | undefined;
	span?: TextSpan | undefined;
}

/**
 * A quarantined secret as returned to callers. Deliberately NON-RETRIEVABLE
 * (ADR-050: credential values are header-only, never persisted retrievably):
 * a short hash fingerprint plus a masked preview — never the value itself.
 */
export interface QuarantinedSecret {
	source: SecretSource;
	ruleId: string;
	/** sha256 hex prefix of the raw value — a stable dedup/audit key. */
	fingerprint: string;
	/** Masked preview, e.g. `AKIA****(len=20)`; `****` for short values. */
	preview: string;
	/** How many occurrences were excised from the scanned text. */
	occurrences: number;
}

/** A PII entity span found by an analyzer, in scanned-text coordinates. */
export interface PiiEntity {
	entityType: string;
	start: number;
	end: number;
	score?: number | undefined;
}

/** Aggregate redaction count per entity type (safe to log/store — no content). */
export interface PiiRedactionSummary {
	entityType: string;
	count: number;
}

/** Detector seam: scan `text`, return hits. Throwing => scrub fails closed. */
export type SecretDetector = (text: string) => Promise<SecretHit[]>;

/** PII analyzer seam: scan `text`, return entity spans. Throwing => fail closed. */
export type PiiAnalyzer = (text: string) => Promise<PiiEntity[]>;

/**
 * Which PII coverage level actually ran — surfaced on the result so callers
 * can gate high-liability writes (e.g. the T2 global tier) on full coverage.
 * `builtin` = deterministic regex layer only (no NER / person names).
 */
export type PiiEngine = "builtin" | "presidio+builtin" | "injected";

/**
 * Injected dependencies. The external tools are seams so the pure core is
 * unit-testable without gitleaks/trufflehog/Presidio on the machine.
 */
export interface ScrubDeps {
	secretDetectors: readonly SecretDetector[];
	piiAnalyzers: readonly PiiAnalyzer[];
	piiEngine: PiiEngine;
	logger?: ActivityLogger | undefined;
}

/** Successful scrub: `clean` mirrors the input shape with unsafe content removed. */
export interface ScrubOk<T> {
	ok: true;
	clean: T;
	quarantined: QuarantinedSecret[];
	pii: PiiRedactionSummary[];
	piiEngine: PiiEngine;
}

/**
 * Fail-closed outcome: the scrubber could not run (engine missing, timeout,
 * malformed report, containment breach). There is NO clean output — the
 * caller MUST treat the input as unsafe to store. `reason` carries no scanned
 * text or secret material.
 */
export interface ScrubFailed {
	ok: false;
	clean: null;
	reason: string;
	quarantined: QuarantinedSecret[];
}

export type ScrubResult<T> = ScrubOk<T> | ScrubFailed;

/**
 * Raised when a scrub engine cannot run or returns something it cannot act on
 * (an unlocatable hit, a malformed report). Always propagates to a fail-closed
 * ScrubFailed — never to a silent pass-through. The `cause` string is
 * truncated by the throw sites so tool stderr cannot smuggle content along.
 */
export class ScrubEngineError extends Error {
	constructor(engine: string, cause: string) {
		super(`scrub engine ${engine} failed: ${cause}`);
		this.name = "ScrubEngineError";
	}
}
