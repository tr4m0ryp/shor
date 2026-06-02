// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
