// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { PlaywrightSession } from "../types/index.js";

/**
 * Playwright session mapping — assigns each agent to a specific session for browser isolation.
 * Keys are `promptTemplate` values from the AGENTS registry.
 */
export const PLAYWRIGHT_SESSION_MAPPING: Record<string, PlaywrightSession> =
	Object.freeze({
		// Phase 1: Pre-reconnaissance
		"pre-recon-code": "agent1",

		// Phase 2: Reconnaissance
		recon: "agent2",

		// Phase 3: Vulnerability Analysis (5 parallel agents)
		"vuln-injection": "agent1",
		"vuln-xss": "agent2",
		"vuln-auth": "agent3",
		"vuln-ssrf": "agent4",
		"vuln-authz": "agent5",

		// Phase 4: Exploitation (5 parallel agents - same as vuln counterparts)
		"exploit-injection": "agent1",
		"exploit-xss": "agent2",
		"exploit-auth": "agent3",
		"exploit-ssrf": "agent4",
		"exploit-authz": "agent5",

		// Phase 4b: Exploit retry pass (same session assignments; runs sequentially
		// after the primary pass so there is no browser contention)
		"exploit-injection-retry": "agent1",
		"exploit-xss-retry": "agent2",
		"exploit-auth-retry": "agent3",
		"exploit-ssrf-retry": "agent4",
		"exploit-authz-retry": "agent5",

		// Phase 5: Reporting
		"report-executive": "agent3",

		// Phase 6: Attack-Surface Synthesis
		"attack-surface": "agent3",
	});
