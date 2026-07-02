// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Progress-liveness watchdog (spec: catch SILENT tool hangs the turn/text
 * watchdog cannot). Public surface: {@link startLivenessMonitor} + its token.
 */

export {
	assessLiveness,
	createLivenessState,
	type Footprint,
	type LivenessAction,
	type LivenessConfig,
	type LivenessState,
	resolveLivenessConfig,
} from "./assess.js";
export {
	LIVENESS_TOKEN_ENV,
	type LivenessMonitor,
	type LivenessMonitorArgs,
	startLivenessMonitor,
} from "./monitor.js";
