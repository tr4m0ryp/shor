// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Consent + enablement gate guarantees (task 014, spec T2). Consent is opt-in
 * and fail-closed: every ambiguous case REFUSES, and the config store defaults
 * to admitting NO tenant.
 */

import { describe, expect, it } from "vitest";
import {
	AUDIT_FLAG,
	CONSENT_ENV,
	POOL_FLAG,
	checkConsent,
	createConfigConsentStore,
	evaluateConsent,
	readAuditPassed,
	readCrossTenantPoolEnabled,
	type ConsentRecord,
} from "./index.js";

const OK: ConsentRecord = { tenantId: "t1", granted: true, basis: "DPA-2026-0001" };

describe("readCrossTenantPoolEnabled / readAuditPassed", () => {
	it("default OFF; only explicit truthy values enable", () => {
		expect(readCrossTenantPoolEnabled({})).toBe(false);
		expect(readAuditPassed({})).toBe(false);
		expect(readCrossTenantPoolEnabled({ [POOL_FLAG]: "1" })).toBe(true);
		expect(readCrossTenantPoolEnabled({ [POOL_FLAG]: "true" })).toBe(true);
		expect(readCrossTenantPoolEnabled({ [POOL_FLAG]: "0" })).toBe(false);
		expect(readCrossTenantPoolEnabled({ [POOL_FLAG]: "yes-ish" })).toBe(false);
		expect(readAuditPassed({ [AUDIT_FLAG]: "on" })).toBe(true);
	});
});

describe("evaluateConsent", () => {
	const now = new Date("2026-07-03T00:00:00Z");

	it("grants a granted, non-revoked, unexpired record with a legal basis", () => {
		expect(evaluateConsent(OK, now).granted).toBe(true);
		expect(evaluateConsent({ ...OK, expiresAt: "2099-01-01T00:00:00Z" }, now).granted).toBe(true);
	});

	it("refuses a null record", () => {
		expect(evaluateConsent(null, now)).toMatchObject({ granted: false });
	});

	it("refuses when not granted / revoked / basis-less / expired", () => {
		expect(evaluateConsent({ ...OK, granted: false }, now).granted).toBe(false);
		expect(evaluateConsent({ ...OK, revoked: true }, now).granted).toBe(false);
		expect(evaluateConsent({ ...OK, basis: "" }, now).granted).toBe(false);
		expect(evaluateConsent({ ...OK, basis: "   " }, now).granted).toBe(false);
		expect(evaluateConsent({ ...OK, expiresAt: "2020-01-01T00:00:00Z" }, now).granted).toBe(false);
	});
});

describe("checkConsent", () => {
	it("returns the store's decision and never throws on a failing lookup", async () => {
		const throwing = { async lookup(): Promise<ConsentRecord | null> {
			throw new Error("db down");
		} };
		const decision = await checkConsent(throwing, "t1");
		expect(decision.granted).toBe(false);
		expect(decision.reason).toContain("consent lookup failed");
	});

	it("grants for a valid record", async () => {
		const store = { async lookup() { return OK; } };
		expect((await checkConsent(store, "t1")).granted).toBe(true);
	});
});

describe("createConfigConsentStore", () => {
	it("admits NO tenant when the config env is unset (default posture)", async () => {
		const store = createConfigConsentStore({});
		expect(await store.lookup("t1")).toBeNull();
	});

	it("reads a JSON array of consent records keyed by tenant", async () => {
		const store = createConfigConsentStore({ [CONSENT_ENV]: JSON.stringify([OK]) });
		expect(await store.lookup("t1")).toMatchObject({ tenantId: "t1", granted: true });
		expect(await store.lookup("other")).toBeNull();
	});

	it("fails closed (empty) on unparseable config", async () => {
		const store = createConfigConsentStore({ [CONSENT_ENV]: "{not json" });
		expect(await store.lookup("t1")).toBeNull();
	});
});
