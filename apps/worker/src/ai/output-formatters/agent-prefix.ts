// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
