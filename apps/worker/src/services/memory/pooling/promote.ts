// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * ============================================================================
 *  CROSS-TENANT RAW-POOLING WRITE PATH — THE HIGHEST-LIABILITY PATH IN SHOR.
 * ============================================================================
 *
 * Promotes a deduped canonical finding (task 013) + its embeddings into the
 * shared, cross-tenant `global_pool` (spec T2 — the user's explicit, informed
 * choice of FULL raw pooling). One tenant's finding becomes retrievable by ALL
 * tenants. Do NOT enable this casually.
 *
 * RESIDUAL RISK — accepted and owned by the user, but NOT to be amplified (F12,
 * R4, and the spec's "Risks & Open Threads" cross-tenant item):
 *   - EMBEDDING INVERSION: Vec2Text reconstructs ~92% of short text from its
 *     vector. A pooled vector is therefore NOT anonymized data — it can leak the
 *     text it came from. This path only ever embeds SCRUBBED text (see below),
 *     so the recoverable text is already secret/PII-free.
 *   - SECRET REGURGITATION: code models memorize + emit credentials (2,702
 *     hard-coded creds extracted from Copilot; ~7% of samples carried secrets).
 *     Scrub is MANDATORY and FAIL-CLOSED here; a live secret is NEVER pooled,
 *     even when the flag is on.
 *   - GDPR / IP EXPOSURE: pooling one tenant's data for another's benefit needs
 *     a legal basis (Art.6/28); Doe v. GitHub shows exposure even for public
 *     code. A logged, explicit tenant consent record is required per write.
 *
 * FOUR GATES, ALL FAIL-CLOSED — the write is a no-op + log unless every one holds:
 *   (0) `SHOR_CROSS_TENANT_POOL` enabled                 (default OFF);
 *   (1) `SHOR_CROSS_TENANT_POOL_AUDIT_PASSED` set        (red-team audit passed);
 *   (2) a valid, current, per-tenant consent record      (DPA/consent basis);
 *   (3) MANDATORY secret/PII scrub succeeds              (fail-closed — task 003).
 * The flag stays OFF until (1)-(2) are operationally true (a compliance
 * sub-project, not a code toggle). Enabling it without those is a breach.
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";
import { verbalize } from "../schema/index.js";
import { scrub } from "../scrub/index.js";
import {
	checkConsent,
	readAuditPassed,
	readCrossTenantPoolEnabled,
} from "./consent.js";
import type {
	FindingLike,
	PoolingContext,
	PoolPromoteDeps,
	PoolRefusal,
	PromoteOutcome,
	Vector,
} from "./types.js";

/** Metadata fields that are free-form enough to carry a leaked secret/PII and so
 *  MUST be scrubbed before pooling (a `source` URL can embed `user:pass@host`). */
const SCRUBBED_META_KEYS = ["route", "source", "sink", "componentVer"] as const;

function refuse(
	logger: ActivityLogger | undefined,
	reason: PoolRefusal,
	detail?: Record<string, unknown>,
): PromoteOutcome {
	logger?.info("pooling: write refused (fail-closed no-op)", { reason, ...detail });
	return { written: false, reason };
}

/**
 * Build the pooled payload from ALREADY-SCRUBBED text/code + the low-risk
 * classification columns. Deliberately does NOT dump the raw finding object —
 * only fields that passed through scrub (or are enum-like classifications) may
 * enter the cross-tenant store.
 */
function buildPayload(
	clean: Record<string, string>,
	meta: {
		cwe: string | null;
		vulnClass: string | null;
		severity: string | null;
		confidence: string | null;
	},
	canonical: FindingLike,
	ctx: PoolingContext,
): Record<string, unknown> {
	const clusterId =
		typeof canonical.cluster_id === "string" ? canonical.cluster_id : null;
	return {
		schema: "pooled_finding.v1",
		doc: clean.text ?? "",
		...(typeof clean.code === "string" ? { code: clean.code } : {}),
		cwe: meta.cwe,
		vulnClass: meta.vulnClass,
		severity: meta.severity,
		confidence: meta.confidence,
		route: clean.route ?? null,
		source: clean.source ?? null,
		sink: clean.sink ?? null,
		componentVer: clean.componentVer ?? null,
		clusterId,
		...(ctx.novelty ? { novelty: ctx.novelty } : {}),
	};
}

/**
 * Verbalize -> scrub -> embed -> insert one canonical finding into the shared
 * cross-tenant pool. Returns `{ written: false, reason }` (a logged no-op) unless
 * all four gates hold. Records `source_tenant` (provenance) and a k-anon seed.
 *
 * IMPORTANT: the vectors are embeddings of the SCRUBBED text/code, never the raw
 * finding — embeddings are invertible (R4), so a vector of raw text would leak.
 */
export async function promoteFindingToPool(
	canonical: FindingLike,
	ctx: PoolingContext,
	deps: PoolPromoteDeps,
): Promise<PromoteOutcome> {
	// Gate 0 — master flag. Default OFF: a stock scan pools nothing.
	if (!(deps.enabled ?? readCrossTenantPoolEnabled())) {
		return refuse(deps.logger, "flag_off");
	}
	// Gate 1 — standing red-team-extraction audit (spec T2 #3).
	if (!(deps.auditPassed ?? readAuditPassed())) {
		return refuse(deps.logger, "audit_not_passed");
	}
	// Gate 2 — explicit, logged, current tenant consent (DPA basis, spec T2 #2).
	const consent = await checkConsent(deps.consent, ctx.tenantId, deps.logger);
	if (!consent.granted) {
		return refuse(deps.logger, "no_consent", { tenant: ctx.tenantId });
	}
	// Cannot derive vectors without an embed server; refuse rather than store
	// naked payloads (retrieval needs the vectors, and a half-write is worse).
	if (!deps.embed.enabled) {
		return refuse(deps.logger, "embed_disabled");
	}

	// Gate 3 — MANDATORY scrub of every string that will be pooled. Bundle the
	// verbalized doc, the code block, AND the free-form metadata into ONE
	// fail-closed pass. A scrub failure aborts the write: nothing is embedded or
	// stored, and (critically) no live secret can reach the shared store.
	const v = verbalize(canonical);
	const bundle: Record<string, string> = { text: v.text };
	if (v.codeBlock) bundle.code = v.codeBlock;
	for (const key of SCRUBBED_META_KEYS) {
		const value = v.metadata[key];
		if (typeof value === "string" && value !== "") bundle[key] = value;
	}
	const scrubbed = await scrub(bundle, deps.scrubDeps);
	if (!scrubbed.ok) {
		deps.logger?.error(
			"pooling: scrub failed closed — finding NOT pooled (no cross-tenant write)",
			{ reason: scrubbed.reason },
		);
		return { written: false, reason: "scrub_failed" };
	}
	const clean = scrubbed.clean;
	const quarantinedSecrets = scrubbed.quarantined.length;
	const piiRedactions = scrubbed.pii.reduce((sum, p) => sum + p.count, 0);
	const kAnonCount = Math.max(1, Math.trunc(ctx.kAnonCount ?? 1));

	try {
		// Embed the SCRUBBED text (Vector A) and code (Vector B) — never raw text.
		const textRes = await deps.embed.embedText([clean.text ?? ""]);
		const vecText: Vector | null = textRes.embeddings[0] ?? null;
		let vecCode: Vector | null = null;
		if (typeof clean.code === "string" && clean.code !== "") {
			const codeRes = await deps.embed.embedCode([clean.code]);
			vecCode = codeRes.embeddings[0] ?? null;
		}

		const payload = buildPayload(
			clean,
			{
				cwe: v.metadata.cwe,
				vulnClass: v.metadata.vulnClass,
				severity: v.metadata.severity,
				confidence: v.metadata.confidence,
			},
			canonical,
			ctx,
		);

		const row = await deps.pool.insert({
			kind: "finding",
			payload,
			vecCode,
			vecText,
			kAnonCount,
			sourceTenant: ctx.tenantId,
		});

		deps.logger?.info("pooling: canonical finding pooled to global tier", {
			poolId: row.id,
			sourceTenant: ctx.tenantId,
			kAnonCount,
			hasCodeVector: vecCode !== null,
			quarantinedSecrets,
			piiRedactions,
		});
		return {
			written: true,
			poolId: row.id,
			quarantinedSecrets,
			piiRedactions,
			kAnonCount,
		};
	} catch (err) {
		const reason = err instanceof Error ? err.message : String(err);
		deps.logger?.error("pooling: embed/insert failed — finding NOT pooled", {
			reason,
		});
		return { written: false, reason: "error" };
	}
}

/**
 * Pool a batch of canonical (deduped) findings, one at a time so a single
 * failure never discards the rest. Returns per-finding outcomes in input order.
 * The CALLER selects cluster representatives from the dedup output (task 013);
 * this helper does not re-run dedup.
 */
export async function promoteFindingsToPool(
	canonicals: readonly FindingLike[],
	ctx: PoolingContext,
	deps: PoolPromoteDeps,
): Promise<PromoteOutcome[]> {
	const outcomes: PromoteOutcome[] = [];
	for (const finding of canonicals) {
		outcomes.push(await promoteFindingToPool(finding, ctx, deps));
	}
	return outcomes;
}
