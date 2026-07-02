// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import type { VulnTypeConfig } from "./types.js";

// Vulnerability type configuration as immutable data.
export const VULN_TYPE_CONFIG: VulnTypeConfig = Object.freeze({
	injection: Object.freeze({
		deliverable: "injection_analysis_deliverable.md",
		queue: "injection_exploitation_queue.json",
	}),
	xss: Object.freeze({
		deliverable: "xss_analysis_deliverable.md",
		queue: "xss_exploitation_queue.json",
	}),
	auth: Object.freeze({
		deliverable: "auth_analysis_deliverable.md",
		queue: "auth_exploitation_queue.json",
	}),
	ssrf: Object.freeze({
		deliverable: "ssrf_analysis_deliverable.md",
		queue: "ssrf_exploitation_queue.json",
	}),
	authz: Object.freeze({
		deliverable: "authz_analysis_deliverable.md",
		queue: "authz_exploitation_queue.json",
	}),
	logic: Object.freeze({
		deliverable: "logic_analysis_deliverable.md",
		queue: "logic_exploitation_queue.json",
	}),
	"misconfig-web": Object.freeze({
		deliverable: "misconfig-web_analysis_deliverable.md",
		queue: "misconfig-web_exploitation_queue.json",
	}),
}) as VulnTypeConfig;
