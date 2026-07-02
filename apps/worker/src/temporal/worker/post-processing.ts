// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import fs from "node:fs";
import path from "node:path";
import { deliverablesDir } from "../../paths.js";

/** Copies all files from the repo's deliverables directory into the requested output path. */
export function copyDeliverables(repoPath: string, outputPath: string): void {
	const outputDir = deliverablesDir(repoPath);
	if (!fs.existsSync(outputDir)) {
		console.log("No deliverables directory found, skipping copy");
		return;
	}

	const files = fs.readdirSync(outputDir);
	if (files.length === 0) {
		console.log("No deliverables to copy");
		return;
	}

	fs.mkdirSync(outputPath, { recursive: true });

	for (const file of files) {
		if (file === ".git") continue;
		const src = path.join(outputDir, file);
		const dest = path.join(outputPath, file);
		fs.cpSync(src, dest, { recursive: true });
	}

	console.log(`Copied ${files.length} deliverable(s) to ${outputPath}`);
}
