// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
