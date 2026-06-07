// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Run-health observability — derive and loudly surface the two silent
 * underperformance signals (screen fail-open rate, vuln tool breadth) so a bad
 * scan announces itself.
 */

export {
	type CategoryScreenHealth,
	classifyVote,
	summarizeCategoryScreen,
	type VoteClass,
} from "./screen.js";
export {
	buildAlerts,
	emitRunHealth,
	type RunHealthReport,
} from "./summary.js";
export {
	type CategoryToolHealth,
	summarizeCategoryTools,
} from "./tools.js";
