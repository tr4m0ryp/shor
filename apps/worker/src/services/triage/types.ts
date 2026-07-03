// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Triage pre-gate types (spec T14).
 *
 * A CHEAP pre-scan check that returns `scan` / `skip` per target-or-category from
 * recon-derived signals, so the engine does not commit an expensive full scan (or a
 * per-category exploitation pass) to a target/surface with no evidence it exists.
 *
 * INVARIANT — the gate never HARD-DROPS a category silently. Every `skip` carries a
 * machine-readable reason and is logged by the orchestrator (`index.ts`). When a
 * signal is missing or ambiguous the gate BIASES TO SCAN (fail-open) — dropping a
 * real target is the expensive mistake, wasting a probe is cheap.
 */

import type { FindingCategory } from "../../job/findings/types.js";

/** Terminal gate outcome for one subject. */
export type TriageDecision = "scan" | "skip";

/** What a verdict is about — a whole target origin, or one exploitation category. */
export type TriageKind = "target" | "category";

/**
 * Cheap reachability signal for a single target origin. `reachabilityDetermined`
 * separates "we probed and it is dead" (a valid skip) from "we never probed"
 * (unknown → bias to scan): a false `reachable` with `reachabilityDetermined=false`
 * must NEVER cause a skip.
 */
export interface TargetSignal {
	/** Origin / base URL the decision is about (used only for logging + the verdict). */
	target: string;
	/** A cheap probe (e.g. httpx / recon origin present) observed the host responding. */
	reachable: boolean;
	/** Whether reachability was actually determined. `false` ⇒ unknown ⇒ bias to scan. */
	reachabilityDetermined: boolean;
}

/**
 * Cheap surface signal for a single exploitation category. `probed` separates "recon
 * looked and found nothing" (a valid skip) from "recon never looked" (unknown → bias
 * to scan). `surfaceHits` is a count of recon evidence hits for this category's attack
 * surface (params/routes/sinks/etc.), derived upstream or via {@link deriveCategorySignals}.
 */
export interface CategorySignal {
	category: FindingCategory;
	/** Recon actually probed for this category's surface. `false` ⇒ unknown ⇒ scan. */
	probed: boolean;
	/** Count of recon evidence hits for this category's surface (0 ⇒ dead surface). */
	surfaceHits: number;
}

/** One gate outcome. A `skip` always carries a human/machine-readable `reason`. */
export interface TriageVerdict {
	kind: TriageKind;
	/** The target origin or the category name. */
	subject: string;
	decision: TriageDecision;
	/** Why this decision was reached — always populated, logged on every skip. */
	reason: string;
	/** Set when the decision would have been `skip` but `observeOnly` forced `scan`. */
	wouldSkip?: boolean;
}

/** Tunables for the gate. All have conservative, bias-to-scan defaults. */
export interface TriageConfig {
	/** Master switch. When false the gate is an identity no-op (all `scan`, silent). */
	enabled: boolean;
	/**
	 * Compute + LOG verdicts but never actually skip (every verdict returns `scan`,
	 * with `wouldSkip` recording the shadow decision). The safe way to trial the gate
	 * on a target before trusting it to drop work. Env: `SHOR_TRIAGE_GATE=observe`.
	 */
	observeOnly: boolean;
	/**
	 * Minimum surface hits for a PROBED category to be scanned. Default 1 — a category
	 * is only skipped when recon probed and found LITERALLY ZERO relevant surface.
	 */
	minCategorySurface: number;
}

/** Input bundle for one triage pass over a target and its categories. */
export interface TriageInput {
	target?: TargetSignal;
	categories?: CategorySignal[];
}

/** Result of a triage pass: every verdict, plus the subjects that were skipped. */
export interface TriageResult {
	verdicts: TriageVerdict[];
	/** Subjects (targets/categories) the gate decided to skip — never silent. */
	skipped: TriageVerdict[];
	/** Categories cleared to scan (identity-equal to the input when disabled). */
	scanCategories: FindingCategory[];
}
