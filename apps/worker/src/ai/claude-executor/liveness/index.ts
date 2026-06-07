// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
