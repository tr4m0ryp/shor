// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { AGENTS } from "../../session-manager.js";

/** Get agent prefix for parallel execution. */
export function getAgentPrefix(description: string): string {
	// Map agent names to their prefixes.
	const agentPrefixes: Record<string, string> = {
		"injection-vuln": "[Injection]",
		"xss-vuln": "[XSS]",
		"auth-vuln": "[Auth]",
		"authz-vuln": "[Authz]",
		"ssrf-vuln": "[SSRF]",
		"injection-exploit": "[Injection]",
		"xss-exploit": "[XSS]",
		"auth-exploit": "[Auth]",
		"authz-exploit": "[Authz]",
		"ssrf-exploit": "[SSRF]",
	};

	// First try to match by agent name directly.
	for (const [agentName, prefix] of Object.entries(agentPrefixes)) {
		const agent = AGENTS[agentName as keyof typeof AGENTS];
		if (agent && description.includes(agent.displayName)) {
			return prefix;
		}
	}

	// Fallback to partial matches for backwards compatibility.
	if (description.includes("injection")) return "[Injection]";
	if (description.includes("xss")) return "[XSS]";
	if (description.includes("authz")) return "[Authz]"; // Check authz before auth
	if (description.includes("auth")) return "[Auth]";
	if (description.includes("ssrf")) return "[SSRF]";

	return "[Agent]";
}
