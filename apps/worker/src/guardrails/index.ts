// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
