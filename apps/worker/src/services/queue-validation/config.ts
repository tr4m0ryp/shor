// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
}) as VulnTypeConfig;
