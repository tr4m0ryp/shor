// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Tool-health preflight — confirm the agents' security tools actually ship in the
 * worker image, so a missing binary is loud instead of a silent no-op.
 */

export {
	EXPECTED_TOOLS,
	parseProbeOutput,
	runToolHealthCheck,
	summarizeToolHealth,
	type ToolHealthSummary,
	type ToolProbe,
} from "./probe.js";
