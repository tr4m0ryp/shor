// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Consent + enablement gates for cross-tenant pooling (task 014, spec T2).
 *
 * Three of the four gates the write path (`promote.ts`) checks live here; the
 * fourth (mandatory scrub) is enforced in `promote.ts` itself:
 *   1. `SHOR_CROSS_TENANT_POOL`               — the master enable flag (default OFF).
 *   2. `SHOR_CROSS_TENANT_POOL_AUDIT_PASSED`  — the red-team-extraction audit flag.
 *   3. a valid, current, per-tenant {@link ConsentRecord} (the DPA/consent basis).
 *
 * ALL gates fail CLOSED: any doubt (missing flag, missing/expired/revoked/basis-
 * less consent, unparseable config) REFUSES the write. Consent is opt-in and
 * NEVER assumed. Every consent decision is LOGGED (counts + reason + a truncated
 * tenant key only — never the record's free-form fields) so the audit trail
 * records exactly which tenant's data was (or was not) admitted to the pool.
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";
import type { ConsentRecord, ConsentStore } from "./types.js";

/** Env name for the master cross-tenant pooling flag. */
export const POOL_FLAG = "SHOR_CROSS_TENANT_POOL";
/** Env name for the standing red-team-extraction audit flag (spec T2 #3). */
export const AUDIT_FLAG = "SHOR_CROSS_TENANT_POOL_AUDIT_PASSED";
/** Env name for the config-backed consent seam (server config, not committed). */
export const CONSENT_ENV = "SHOR_CROSS_TENANT_POOL_CONSENT";

function truthy(raw: string | undefined): boolean {
	const v = raw?.trim().toLowerCase();
	return v === "1" || v === "true" || v === "yes" || v === "on";
}

/** True only when `SHOR_CROSS_TENANT_POOL` is explicitly truthy. Default OFF. */
export function readCrossTenantPoolEnabled(
	env: NodeJS.ProcessEnv = process.env,
): boolean {
	return truthy(env[POOL_FLAG]);
}

/** True only when the red-team-extraction audit flag is set. Default OFF. */
export function readAuditPassed(
	env: NodeJS.ProcessEnv = process.env,
): boolean {
	return truthy(env[AUDIT_FLAG]);
}

/** A consent decision plus a short, content-free reason for the audit log. */
export interface ConsentDecision {
	readonly granted: boolean;
	readonly reason: string;
}

/**
 * Evaluate a raw consent record against the T2 requirements. Pure + total:
 * a `null` record, an ungranted/revoked one, one with no legal `basis`, or one
 * past its `expiresAt` all yield `{ granted: false }`. Only a granted,
 * non-revoked, unexpired record carrying a non-empty `basis` grants.
 */
export function evaluateConsent(
	record: ConsentRecord | null,
	now: Date = new Date(),
): ConsentDecision {
	if (!record) return { granted: false, reason: "no consent record" };
	if (record.granted !== true) return { granted: false, reason: "consent not granted" };
	if (record.revoked === true) return { granted: false, reason: "consent revoked" };
	if (typeof record.basis !== "string" || record.basis.trim() === "") {
		return { granted: false, reason: "no legal basis on record" };
	}
	if (record.expiresAt) {
		const expiry = Date.parse(record.expiresAt);
		if (!Number.isNaN(expiry) && expiry <= now.getTime()) {
			return { granted: false, reason: "consent expired" };
		}
	}
	return { granted: true, reason: "explicit consent on file" };
}

/**
 * Look up + evaluate a tenant's consent, LOGGING the decision. Any store error
 * fails CLOSED (refuse) — a flaky consent lookup can never admit a write.
 */
export async function checkConsent(
	store: ConsentStore,
	tenantId: string,
	logger?: ActivityLogger,
	now: Date = new Date(),
): Promise<ConsentDecision> {
	let decision: ConsentDecision;
	try {
		const record = await store.lookup(tenantId);
		decision = evaluateConsent(record, now);
	} catch (err) {
		const reason = err instanceof Error ? err.message : String(err);
		decision = { granted: false, reason: `consent lookup failed: ${reason}` };
	}
	// Audit trail: log the tenant + verdict only, never the record's fields.
	logger?.info("pooling: consent check", {
		tenant: tenantId,
		granted: decision.granted,
		reason: decision.reason,
	});
	return decision;
}

/**
 * A config-backed {@link ConsentStore} — the seam for the consent list that
 * lives in SERVER CONFIG, not this repository (mirrors the guest-access-code
 * config seam: no consent data is committed here). Reads a JSON array of
 * {@link ConsentRecord} from `SHOR_CROSS_TENANT_POOL_CONSENT`. An unset or
 * unparseable value yields an empty store — every lookup returns `null`, so the
 * write path refuses. This is intentional: the default posture is NO consent.
 */
export function createConfigConsentStore(
	env: NodeJS.ProcessEnv = process.env,
	logger?: ActivityLogger,
): ConsentStore {
	const byTenant = new Map<string, ConsentRecord>();
	const raw = env[CONSENT_ENV]?.trim();
	if (raw) {
		try {
			const parsed = JSON.parse(raw) as unknown;
			const list = Array.isArray(parsed) ? parsed : [];
			for (const item of list) {
				if (item && typeof item === "object" && typeof (item as ConsentRecord).tenantId === "string") {
					const rec = item as ConsentRecord;
					byTenant.set(rec.tenantId, rec);
				}
			}
		} catch (err) {
			// Fail closed: an unparseable consent config admits NO tenant.
			const reason = err instanceof Error ? err.message : String(err);
			logger?.error("pooling: consent config unparseable — NO tenant admitted", { reason });
		}
	}
	return {
		async lookup(tenantId: string): Promise<ConsentRecord | null> {
			return byTenant.get(tenantId) ?? null;
		},
	};
}
