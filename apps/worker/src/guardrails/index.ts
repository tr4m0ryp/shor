// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Worker-side guardrails (LAUNCH-SPEC §5.6, §3.3) — the engine's network guard.
 *
 * The dashboard owns RoE authoring/validation, rate-limit/audit/kill-switch
 * policy, and egress derivation (`apps/web/.../guardrails`). The worker carries
 * only the runtime CHECK it must run inside the sandbox before any outbound
 * action: `assertNetworkAllowed(url)`.
 */

export {
	GITHUB_APP_HOSTS,
	NetworkGuardError,
	assertNetworkAllowed,
	isNetworkAllowed,
	resetNetworkGuard,
} from "./network-guard.js";

export {
	METADATA_HOSTNAMES,
	METADATA_IP,
	isBlockedHost,
	isBlockedIpv4,
	isBlockedIpv6,
} from "./net.js";

export {
	type Roe,
	type RoeHostRule,
	type RoeScheme,
	RoeViolationError,
	assertInScope,
	isInScope,
} from "./roe.js";
