// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from "zx";
import { PentestError } from "../error-handling.js";
import type { IncludeReplacement } from "./types.js";

/**
 * Process `@include(path)` directives in a template by reading the referenced
 * files relative to `baseDir`. Rejects path-traversal attempts that escape the
 * base directory.
 */
export async function processIncludes(
	content: string,
	baseDir: string,
): Promise<string> {
	const includeRegex = /@include\(([^)]+)\)/g;
	const resolvedBase = path.resolve(baseDir);

	const replacements: IncludeReplacement[] = await Promise.all(
		Array.from(content.matchAll(includeRegex)).map(async (match) => {
			const rawPath = match[1] ?? "";
			const includePath = path.resolve(baseDir, rawPath);
			if (
				!includePath.startsWith(resolvedBase + path.sep) &&
				includePath !== resolvedBase
			) {
				throw new PentestError(
					`Path traversal detected in @include(): ${rawPath}`,
					"prompt",
					false,
					{
						includePath,
						baseDir: resolvedBase,
					},
				);
			}
			const sharedContent = await fs.readFile(includePath, "utf8");
			return {
				placeholder: match[0],
				content: sharedContent,
			};
		}),
	);

	for (const replacement of replacements) {
		content = content.replace(replacement.placeholder, replacement.content);
	}
	return content;
}
