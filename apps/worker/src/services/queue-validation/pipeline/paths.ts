// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
