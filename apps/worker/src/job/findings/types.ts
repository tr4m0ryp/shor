// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Local types for the findings-emission step (ADR-051 → dashboard contract).
 *
 * `FindingRecord` mirrors the Shor web `FindingRecord` (LAUNCH-SPEC §6.1)
 * verbatim — the worker and the web sink share this exact shape. We redeclare
 * it here rather than import across the app boundary: the worker package does
 * not depend on `@shor/web`.
 */

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
/**
 * §6.1 confidence ladder, plus one worker-internal rung. `unverified` is used
 * ONLY for `unverified_out_of_scope` findings (see {@link VulnDisposition}): it
 * means "not seen in analyzed source, not live-confirmed". Such records are
 * routed to the manual-review appendix and EXCLUDED from the emitted set, so
 * this value is never POSTed to the dashboard sink.
 */
export type FindingConfidence = 'confirmed' | 'firm' | 'tentative' | 'unverified';

/**
 * Human-readable explanation of WHY a finding is not `confirmed`. Always
 * empty for `exploited` dispositions; populated for every other outcome so the
 * dashboard and attack surface can surface a specific failure reason rather than
 * a bare "firm" label.
 *
 * Categories (maps to `VulnDisposition`):
 *   - `blocked_waf`       – live probe intercepted by WAF / security control
 *   - `blocked_auth`      – endpoint requires authentication we did not hold
 *   - `blocked_ratelimit` – rate-limited during exploitation attempt
 *   - `blocked_internal`  – endpoint not externally reachable (internal/VPN only)
 *   - `blocked`           – blocked, specific reason not identifiable from evidence
 *   - `unproven`          – queued hypothesis; no live validation evidence produced
 *   - `excluded`          – enforcing tier not in analyzed source (unverified_out_of_scope)
 */
export type ValidationFailureReason =
  | 'blocked_waf'
  | 'blocked_auth'
  | 'blocked_ratelimit'
  | 'blocked_internal'
  | 'blocked'
  | 'unproven'
  | 'excluded';
export type FindingStatus = 'new' | 'open' | 'fixed' | 'regressed';

/**
 * Disposition of a normalized vuln as it flows through collection.
 *   - `exploited` — proven live (evidence markdown); never gated out.
 *   - `blocked`   — attempted but validation/defense blocked it.
 *   - `queued`    — a hypothesis from the analysis queue, not yet exploited.
 *   - `screen_uncertain` — the adversarial screen panel neither confirmed nor
 *     refuted this hypothesis. NON-terminal: unlike the terminal
 *     `unverified_screen_rejected`, it flows THROUGH to exploitation (treated like
 *     a live hypothesis), so the screen alone never routes it to the appendix.
 *   - `unverified_out_of_scope` (T3, gating) — the tier that would enforce this
 *     finding's control was NOT in the analyzed source AND it was not
 *     live-confirmed. Terminal: excluded from the emitted findings and routed
 *     to the manual-review appendix. Distinct from `tentative` (weak-but-seen).
 *   - `unverified_screen_rejected` — the adversarial screen agent refuted this
 *     hypothesis before exploitation (recorded in `{category}_screen_rejected.json`).
 *     Treated identically to `unverified_out_of_scope` for emission: excluded from
 *     the emitted set and the attack surface, routed to the manual-review appendix
 *     for audit. Distinct so the appendix can label WHY it was set aside.
 *   - `out_of_scope_target` (T3) — the "exploit" landed on the harness's own mock /
 *     a host with no analyzed repo source / `reachability === "HARNESS_ONLY"`, so it
 *     proves nothing about the real target. TERMINAL: routed to the manual-review
 *     appendix (Task 002), never emitted. Declared here so the type exists wave-wide.
 *   - `exploited_privileged` (T3) — an authz / privilege-escalation "exploit" only
 *     ever performed by an already-privileged identity: its premise is invalid (no
 *     privilege boundary was actually crossed). TERMINAL: routed to the appendix
 *     (Task 002), never emitted.
 *   - `refuted_on_review` (T3) — a later adversarial false-positive pass refuted a
 *     previously `confirmed` / `critical` finding with target source in context.
 *     TERMINAL: routed to the appendix (Task 002), never emitted.
 */
export type VulnDisposition =
  | 'exploited'
  | 'blocked'
  | 'queued'
  | 'screen_uncertain'
  | 'unverified_out_of_scope'
  | 'unverified_screen_rejected'
  | 'out_of_scope_target'
  | 'exploited_privileged'
  | 'refuted_on_review';

/**
 * Reachability of a finding's vulnerable code from an external entrypoint, set by
 * the reachability pass and carried on {@link FindingRecord}. Exported so the
 * later precision modules import this union instead of re-declaring it.
 *   - `REACHABLE`    — reached from an external / untrusted entrypoint.
 *   - `HARNESS_ONLY` — only reachable via a test/harness, not live traffic.
 *   - `UNCLEAR`      — reachability could not be determined.
 */
export type Reachability = 'REACHABLE' | 'HARNESS_ONLY' | 'UNCLEAR';

/**
 * Outcome of the exploitation oracle's replay attempt for a finding — distinct
 * from the collection-time {@link VulnDisposition}. Exported so the later
 * precision modules import this union instead of re-declaring it.
 *   - `exploited`      — the oracle replayed the PoC and it succeeded.
 *   - `blocked`        — the replay was blocked (defense / WAF / auth / etc.).
 *   - `not_replayable` — the PoC could not be deterministically replayed.
 */
export type OracleDisposition = 'exploited' | 'blocked' | 'not_replayable';

/** file:line location for code findings (§6.1). */
export interface VulnerableCodeLocation {
  file: string;
  line: number;
}

/** Structured finding record — mirrors LAUNCH-SPEC §6.1. */
export interface FindingRecord {
  id: string;
  /**
   * Human-readable explanation of why this finding is not `confirmed`. Empty
   * for `exploited` (confirmed) dispositions. Populated for `blocked`,
   * `queued`, and `unverified_out_of_scope`. Use the `ValidationFailureReason`
   * enum values but stored as a plain string for forward-compatibility.
   * Example: "Blocked — WAF / security control intercepted the probe".
   */
  validation_note: string;
  /**
   * Human-readable finding title (e.g. "Stored XSS", "Token Management Issue").
   * Always synthesized at mapping time from the weakness type so the dashboard
   * never falls back to the bare category ("xss"/"auth"); the Sinas improver may
   * later overwrite it with a sharper, location-specific title.
   */
  title: string;
  category: string;
  cwe: string;
  owasp_category: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  evidence: string;
  safe_poc: string;
  repro_steps: string[];
  vulnerable_code_location: VulnerableCodeLocation;
  missing_defense: string;
  remediation: string;
  status: FindingStatus;
  fingerprint: string;
  partialFingerprints: Record<string, string>;
  /**
   * Collection-time disposition (forwarded from the source vuln). Present so the
   * coverage gate can route `unverified_out_of_scope` records to the manual-
   * review appendix; emitted findings carry `exploited`/`blocked`/`queued`. Not
   * part of the web §6.1 surface — carried via the index signature below.
   */
  disposition?: VulnDisposition;
  /**
   * Reachability of the vulnerable code from an external entrypoint (set by the
   * reachability pass). OPTIONAL / back-compat: absent on records from emitters
   * that predate it. Not part of the web §6.1 surface — carried via the index
   * signature below.
   */
  reachability?: Reachability;
  /**
   * Stable key grouping near-duplicate findings into one cluster. Added ALONGSIDE
   * `fingerprint` (which is unchanged); a later task populates it. OPTIONAL /
   * back-compat.
   */
  cluster_id?: string;
  /**
   * Outcome of the exploitation oracle's replay attempt — distinct from the
   * collection-time `disposition`. OPTIONAL / back-compat.
   */
  oracle_disposition?: OracleDisposition;
  /**
   * Id of the threat / attack-scenario this finding maps to. OPTIONAL /
   * back-compat.
   */
  threat_id?: string;
  /**
   * Evidence axes (T1) — independent of `disposition`. They only ever DOWN-adjust
   * an over-confident confidence/severity (see `deriveConfidence`/`deriveSeverity`
   * in `mapping/scoring.ts`); they never invent confidence. ALL OPTIONAL /
   * back-compat: when absent, scoring is byte-identical to the disposition-only path.
   */
  /** The cited code construct was verified present at file:line in analyzed source. */
  code_confirmed?: boolean;
  /**
   * The finding's premise holds (e.g. a real privilege boundary was crossed, not an
   * already-privileged identity acting on itself). `false` falsifies an `exploited`
   * claim and down-adjusts its score.
   */
  premise_valid?: boolean;
  /**
   * The target hit is in analyzed scope (not the harness's own mock / a no-source
   * host). `false` (scaffolding / out-of-scope target) down-adjusts an `exploited`
   * claim — exploiting a mock proves nothing about the target.
   */
  in_scope?: boolean;
  /**
   * The CWE was NOT derived from the entry or a mechanism map — it fell through to
   * the category default (`mapping/cwe-map.ts`). The finalize layer flags inferred
   * CWEs. OPTIONAL / back-compat.
   */
  cwe_inferred?: boolean;
  /**
   * Result of the cite-line verifier (`mapping/verify-location.ts`): `true` when the
   * cited line plausibly contained the asserted construct, `false` when it did not.
   * LEFT UNDEFINED (not `false`) when verification could not run — fail-open.
   */
  location_verified?: boolean;
  /**
   * Set TRUE by the dev-credential guard (`dev-credential-guard.ts`) when a hardcoded-
   * secret finding is an intentional local/dev placeholder (test-marker comment,
   * placeholder/doubled-fake value) that production overrides — demoted to `low`, not a
   * leaked production secret. OPTIONAL / back-compat.
   */
  dev_credential_scaffolding?: boolean;
  /**
   * Fingerprints / ids of other findings folded into this one as duplicates by the
   * finalize dedup-collapse (T6). Members are preserved (recall-safe); the report
   * shows the cluster once. OPTIONAL / back-compat.
   */
  also_reported_as?: string[];
  [key: string]: unknown;
}

/** Body POSTed to the findings sink per the shared contract. */
export interface FindingsSinkPayload {
  findings: FindingRecord[];
  attackSurface?: Record<string, unknown>;
  /**
   * The structured finalized executive report (cli-finalization stage 3). Posted so
   * the dashboard serves `/scans/:id/report` from the DB (the Sinas report store is
   * decommissioned). Optional — absent when finalize did not produce one.
   */
  report?: Record<string, unknown>;
  // `running` is used for incremental mid-run posts (findings accrue in the DB
  // as agents finish); the sink only transitions the scan on completed/failed.
  status: 'completed' | 'failed' | 'running';
}

/** The vulnerability categories the pipeline produces queues for. */
export type FindingCategory = 'injection' | 'xss' | 'auth' | 'ssrf' | 'authz' | 'logic' | 'misconfig-web';

/**
 * A normalized vulnerability drawn from a per-category exploitation queue,
 * optionally enriched with the live disposition from the evidence markdown.
 * Field names vary across queues; we keep the raw object plus the extracted,
 * category-agnostic fields the mapper needs.
 */
export interface NormalizedVuln {
  category: FindingCategory;
  id: string;
  raw: Record<string, unknown>;
  /**
   * `exploited` if the evidence MD lists it as proven; `queued` otherwise. The
   * coverage gate may later set `unverified_out_of_scope` (see {@link VulnDisposition}).
   */
  disposition: VulnDisposition;
  /** Exploitation-evidence prose for this VULN-ID, when present. */
  evidenceText: string;
  /**
   * Evidence axes (T1), set by a precision pass (Task 002 gating) BEFORE mapping.
   * Both OPTIONAL: when absent (today's collection path), scoring is byte-identical
   * to the disposition-only behavior — they only ever DOWN-adjust an `exploited`
   * claim. The mapper copies a present value onto the emitted {@link FindingRecord}.
   */
  /** The target hit is in analyzed scope (not the harness mock / a no-source host). */
  in_scope?: boolean;
  /** The finding's premise holds (a real privilege boundary was crossed, etc.). */
  premise_valid?: boolean;
}

/** Raw queue wrapper shape: `{ vulnerabilities: [...] }`. */
export interface RawQueue {
  vulnerabilities?: unknown[];
  [key: string]: unknown;
}
