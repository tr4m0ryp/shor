// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Types for the cross-tenant raw-pooling write path (task 014, spec T2 + R4).
 *
 * THIS IS THE HIGHEST-LIABILITY PATH IN THE BUILD. It writes a deduped canonical
 * finding + its embeddings into the shared cross-tenant `global_pool` (T2 — the
 * user's explicit choice of full raw pooling). Everything here is a plain shape
 * so the promote logic stays pure and unit-testable; the pgvector repository
 * (apps/web) is reached through an injected PORT (mirroring
 * `../write/persist.ts`), never imported across the package boundary.
 *
 * Residual risk this path accepts and MUST NOT amplify (F12 / R4):
 *   - embedding inversion (Vec2Text reconstructs ~92% of short text) — so the
 *     pooled vectors MUST be embeddings of SCRUBBED text, never raw text;
 *   - secret regurgitation (code models memorize + leak credentials) — so scrub
 *     is mandatory and fail-closed; live secrets are NEVER pooled;
 *   - GDPR / IP exposure (Art.6/28; Doe v. GitHub even for public code) — so a
 *     logged DPA/consent record is required before any write.
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";
import type { NoveltyLabel } from "../dedup/index.js";
import type { EmbedClient } from "../embed/index.js";
import type { FindingLike } from "../schema/index.js";
import type { ScrubDeps } from "../scrub/index.js";

/** A dense embedding — the pgvector repos expect a 1024-dim number array. */
export type Vector = readonly number[];

/**
 * Provenance + scope for a pooled finding. `tenantId` becomes the pool row's
 * `source_tenant` (provenance only — retrieval is cross-tenant). `kAnonCount`
 * seeds the row's k-anonymity aggregate; first pool from one tenant is 1, and
 * `globalPoolRepo.bumpKAnon` raises it when another tenant rediscovers it.
 */
export interface PoolingContext {
	readonly tenantId: string;
	readonly projectId: string;
	readonly scanId?: string | null;
	/** k-anonymity seed for the pooled row; clamped to >= 1. Default 1. */
	readonly kAnonCount?: number;
	/** Dedup novelty of the canonical finding (task 013), for the payload. */
	readonly novelty?: NoveltyLabel;
}

/**
 * An explicit, logged tenant consent record — precondition (2) for pooling
 * (GDPR Art.6/28: a DPA/consent legal basis that "cannot be buried in ToS").
 * Absence, revocation, expiry, or a missing legal `basis` all REFUSE the write.
 */
export interface ConsentRecord {
	readonly tenantId: string;
	/** Must be explicitly `true`; any other value refuses. */
	readonly granted: boolean;
	/** Legal-basis reference (DPA id / signed contract clause). Non-empty required. */
	readonly basis: string;
	/** Who recorded the grant + when (audit trail). */
	readonly grantedBy?: string | null;
	readonly grantedAt?: string | null;
	/** Optional ISO expiry; a past expiry revokes consent. */
	readonly expiresAt?: string | null;
	/** Explicit withdrawal (GDPR Art.7(3) right to withdraw) — refuses if true. */
	readonly revoked?: boolean;
}

/**
 * Consent lookup port. Returns the record for a tenant, or `null` when none
 * exists (which REFUSES the write — consent is opt-in, never assumed). The real
 * source is server-side config / a consent table, injected at wiring time.
 */
export interface ConsentStore {
	lookup(tenantId: string): Promise<ConsentRecord | null>;
}

/**
 * Global-pool writer port. The real `globalPoolRepo.insert` (apps/web) satisfies
 * this structurally; the worker never imports `pg` / the web package directly.
 */
export interface GlobalPoolWriter {
	insert(input: {
		kind: "abstraction" | "exemplar" | "finding";
		payload: Record<string, unknown>;
		vecCode?: Vector | null;
		vecText?: Vector | null;
		kAnonCount?: number;
		sourceTenant?: string | null;
	}): Promise<{ id: string }>;
}

/** Injected collaborators for {@link promoteFindingToPool}. */
export interface PoolPromoteDeps {
	readonly embed: EmbedClient;
	readonly scrubDeps: ScrubDeps;
	readonly consent: ConsentStore;
	readonly pool: GlobalPoolWriter;
	readonly logger?: ActivityLogger | undefined;
	/** Override the `SHOR_CROSS_TENANT_POOL` env gate (mainly for tests). */
	readonly enabled?: boolean | undefined;
	/** Override the `SHOR_CROSS_TENANT_POOL_AUDIT_PASSED` gate (mainly for tests). */
	readonly auditPassed?: boolean | undefined;
}

/**
 * Why a pool write was refused. Every value is a fail-closed no-op + log — the
 * path NEVER writes when any precondition is absent.
 *   - `flag_off`         — `SHOR_CROSS_TENANT_POOL` is not enabled (the default).
 *   - `audit_not_passed` — the red-team-extraction audit flag is not set.
 *   - `no_consent`       — no valid, current tenant consent record.
 *   - `embed_disabled`   — no embed server configured (cannot derive vectors).
 *   - `scrub_failed`     — mandatory scrub could not run (fail closed).
 *   - `error`            — embed/insert threw.
 */
export type PoolRefusal =
	| "flag_off"
	| "audit_not_passed"
	| "no_consent"
	| "embed_disabled"
	| "scrub_failed"
	| "error";

/** Outcome of a single-finding pool promotion. */
export type PromoteOutcome =
	| {
			readonly written: true;
			readonly poolId: string;
			readonly quarantinedSecrets: number;
			readonly piiRedactions: number;
			readonly kAnonCount: number;
	  }
	| {
			readonly written: false;
			readonly reason: PoolRefusal;
	  };

/** Re-export so callers building canonical findings need one import. */
export type { FindingLike };
