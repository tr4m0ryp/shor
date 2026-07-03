// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Shared types for the executable-oracle replay runner (T9).
 *
 * A PoC is the machine-readable, replayable proof an exploit agent writes for
 * each finding it claims to have exploited (`{category}_poc.json`). The oracle
 * re-executes it deterministically and observes the declared `expected_signal`
 * to decide `exploited` / `blocked` / `not_replayable` — an EXECUTABLE verdict,
 * not a prose parse.
 */

import type { OracleDisposition } from "../../../job/findings/types.js";
import type { ActivityLogger } from "../../../types/activity-logger.js";

export type { OracleDisposition };

/**
 * The WIDENED replay disposition (T7). The persisted/web {@link OracleDisposition}
 * stays a strict subset (`exploited | blocked | not_replayable`) for the sink; the
 * integration layer (task 008) adds two first-class outcomes ON TOP of it:
 *   - `inconclusive_infra` — a guard-reject / timeout / 5xx / failed-whoami /
 *     unwired-executor outcome. NEVER counts as a refutation (fail-open on
 *     demotion) and is carried distinctly so it is auditable, not silently folded
 *     into a `blocked` verdict (Ali's collapse loses exactly this).
 *   - `needs_review` — a positive proof whose CALIBRATED confidence gated below
 *     threshold: held for manual review, never a silent `exploited` (fail-closed
 *     on promotion).
 * Only the two subset values are ever written to `oracle_dispositions.json`; the
 * wider two are stamped on the finding record for audit + routing.
 */
export type ReplayDisposition = OracleDisposition | "inconclusive_infra" | "needs_review";

/** How a PoC is replayed. */
export type PocKind = "http" | "browser" | "oob";

/**
 * The observable that proves the exploit reproduced.
 *   - `sql_log` — the white-box SQL query-log oracle (007): the payload landed
 *     inline in an executed statement (injected) vs only as a bound parameter.
 */
export type SignalType = "status" | "reflection" | "oob" | "data" | "sql_log";

export interface ExpectedSignal {
	type: SignalType;
	/**
	 * For `status`: the HTTP status code. For `reflection`/`data`: a substring that
	 * must appear in the response body. For `oob`: the out-of-band correlation token.
	 */
	match: string | number;
}

/** A single replayable HTTP request. */
export interface PocRequest {
	method: string;
	url: string;
	headers?: Record<string, string>;
	body?: string;
}

/** One replayable proof-of-concept for a finding. */
export interface Poc {
	id: string;
	kind: PocKind;
	request?: PocRequest;
	browser_script?: string;
	expected_signal: ExpectedSignal;
	/**
	 * Explicit "this replay has NO side effects" vouch from the exploit agent. The
	 * read-only safety gate uses it to allow replaying a non-GET/HEAD request; absent
	 * it, only idempotent GET/HEAD are auto-replayed.
	 */
	safe?: boolean;
	/**
	 * Forward-compat identity hints for differential authz confirmation (T1): the
	 * identity the exploit ran AS, and (for IDOR) the victim whose resource it
	 * touched. The differential oracle decides `premise_valid` by replaying under
	 * LOWER-privilege identities regardless of these hints.
	 */
	attacker_identity?: string;
	victim_identity?: string;
}

/**
 * What an executor observed (or why it could not). Discriminated on `observed`.
 * `rate_limited` triggers backoff + a `not_replayable` verdict; `error` (transport
 * failure) and `not_replayable` (missing/unwired) both fall back to the markdown
 * parse without asserting a `blocked` verdict.
 */
export type ExecOutcome =
	| {
			observed: true;
			status?: number;
			body?: string;
			oobObserved?: boolean;
			/**
			 * White-box SQL query-log verdict (007), when the query-log oracle was
			 * correlated to this replay. OPTIONAL / back-compat: absent on every
			 * executor that does not consult the DB log.
			 */
			sqlLogVerdict?: "injected" | "parameterized" | "not_found" | "unavailable";
	  }
	| {
			observed: false;
			reason: "rate_limited" | "not_replayable" | "error";
			detail?: string;
	  };

/** Runtime dependencies an executor needs; all defaulted by the runner. */
export interface ExecCtx {
	/** Outbound HTTP transport (defaults to the worker's global `fetch`). */
	fetchImpl: typeof fetch;
	/** Network guard — MUST wrap every outbound request (default-deny egress). */
	assertAllowed: (url: string) => void;
	/** Per-request timeout in ms; `<= 0` disables the abort timer. */
	timeoutMs: number;
	logger: ActivityLogger;
	/**
	 * Identity whose auth REPLACES the PoC's captured auth on the replayed request
	 * (differential authz, T1): the executor strips the PoC's own `Authorization`/
	 * `Cookie` and applies these headers instead. Absent ⇒ the request fires with the
	 * PoC's own headers (the privileged baseline). Header VALUES are USED to build the
	 * request but are NEVER logged or surfaced (ADR-050).
	 */
	currentIdentity?: { label: string; headers: Record<string, string> };
}

/** Replays one PoC of a given {@link PocKind} and reports what it observed. */
export type Executor = (poc: Poc, ctx: ExecCtx) => Promise<ExecOutcome>;

/** The executor for each {@link PocKind}. Injectable so a future session can wire
 * real browser / OOB runners without touching the call site. */
export interface ExecutorSet {
	http: Executor;
	browser: Executor;
	oob: Executor;
}
