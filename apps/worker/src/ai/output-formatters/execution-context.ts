// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { extractAgentType } from "../../utils/formatting.js";
import type { ExecutionContext } from "../types.js";

export function detectExecutionContext(description: string): ExecutionContext {
	const isParallelExecution =
		description.includes("vuln agent") || description.includes("exploit agent");

	const useCleanOutput =
		description.includes("Pre-recon agent") ||
		description.includes("Recon agent") ||
		description.includes("Executive Summary and Report Cleanup") ||
		description.includes("vuln agent") ||
		description.includes("exploit agent");

	const agentType = extractAgentType(description);

	const agentKey = description.toLowerCase().replace(/\s+/g, "-");

	return { isParallelExecution, useCleanOutput, agentType, agentKey };
}
