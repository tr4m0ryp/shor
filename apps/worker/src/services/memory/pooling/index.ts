// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Cross-tenant raw-pooling write path — public surface (task 014, spec T2).
 *
 * THE HIGHEST-LIABILITY PATH IN THE BUILD. Default-OFF and fail-closed: a stock
 * scan pools nothing. The eventual sink integration selects deduped canonical
 * findings (task 013) and wires the real `globalPoolRepo` (apps/web) into the
 * {@link GlobalPoolWriter} port:
 *   import { promoteFindingToPool, createConfigConsentStore }
 *     from "../memory/pooling/index.js";
 *
 * The flag MUST stay OFF until the compliance prerequisites (red-team audit +
 * DPA/consent basis) are operationally in place — see promote.ts.
 */

export {
	AUDIT_FLAG,
	CONSENT_ENV,
	POOL_FLAG,
	checkConsent,
	createConfigConsentStore,
	evaluateConsent,
	readAuditPassed,
	readCrossTenantPoolEnabled,
	type ConsentDecision,
} from "./consent.js";
export { promoteFindingToPool, promoteFindingsToPool } from "./promote.js";
export type {
	ConsentRecord,
	ConsentStore,
	FindingLike,
	GlobalPoolWriter,
	PoolingContext,
	PoolPromoteDeps,
	PoolRefusal,
	PromoteOutcome,
	Vector,
} from "./types.js";
