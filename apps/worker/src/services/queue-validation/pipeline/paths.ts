// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { path } from "zx";
import type { VulnType } from "../../../types/agents.js";
import { PentestError } from "../../error-handling.js";
import { VULN_TYPE_CONFIG } from "../config.js";
import type { PathsBase, PathsWithError } from "../types.js";

// Pure function to create file paths for a vulnerability type's deliverable + queue.
export const createPaths = (
	vulnType: VulnType,
	sourceDir: string,
): PathsBase | PathsWithError => {
	const config = VULN_TYPE_CONFIG[vulnType];
	if (!config) {
		return {
			error: new PentestError(
				`Unknown vulnerability type: ${vulnType}`,
				"validation",
				false,
				{ vulnType },
			),
		};
	}

	return Object.freeze({
		vulnType,
		deliverable: path.join(sourceDir, config.deliverable),
		queue: path.join(sourceDir, config.queue),
		sourceDir,
	});
};
