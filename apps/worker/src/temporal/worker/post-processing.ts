// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
