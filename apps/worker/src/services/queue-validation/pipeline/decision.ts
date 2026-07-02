// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import type { ExploitationDecision } from "../../../types/agents.js";
import type { PathsWithError, PathsWithQueue } from "../types.js";

// Final decision: skip if queue says no vulns, proceed if vulns found, error otherwise.
export const determineExploitationDecision = (
	validatedData: PathsWithQueue | PathsWithError,
): ExploitationDecision => {
	if ("error" in validatedData) {
		throw validatedData.error;
	}

	const hasVulnerabilities = validatedData.queueData.vulnerabilities.length > 0;

	// Rule 4: Both exist, queue valid and populated
	// Rule 5: Both exist, queue valid but empty
	return Object.freeze({
		shouldExploit: hasVulnerabilities,
		shouldRetry: false,
		vulnerabilityCount: validatedData.queueData.vulnerabilities.length,
		vulnType: validatedData.vulnType,
	});
};
