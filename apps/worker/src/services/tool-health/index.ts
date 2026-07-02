// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
