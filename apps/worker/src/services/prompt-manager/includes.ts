// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from "zx";
import { PentestError } from "../error-handling.js";

/** Matches a single `@include(relative/path.txt)` directive. */
const INCLUDE_REGEX = /@include\(([^)]+)\)/g;

/**
 * Backstop against pathological (non-cyclic) deep nesting. True cycles are
 * caught exactly by the resolution-stack guard; this cap only bounds a
 * legitimately deep include chain so a malformed tree can never run away.
 */
const MAX_INCLUDE_DEPTH = 10;

/**
 * Process `@include(path)` directives in a template by reading the referenced
 * files relative to `baseDir`.
 *
 * Resolution is RECURSIVE to a fixpoint: an `@include` nested inside an
 * already-included file is itself expanded, repeating until no directive
 * remains (previously single-pass, which silently dropped nested includes such
 * as the authorization framing in `_vuln-scope.txt`/`_exploit-scope.txt`).
 *
 * Every resolved path is re-checked against the base directory at EVERY level
 * (path-traversal guard), include cycles are detected via the active resolution
 * stack, and {@link MAX_INCLUDE_DEPTH} bounds runaway nesting. Paths resolve
 * relative to `baseDir` at every level (matching how prompts author nested
 * includes root-relative), so the base dir is constant through the recursion.
 */
export async function processIncludes(
	content: string,
	baseDir: string,
): Promise<string> {
	const resolvedBase = path.resolve(baseDir);
	return resolveIncludes(content, baseDir, resolvedBase, []);
}

/**
 * Expand every `@include(...)` in `content`. `stack` holds the absolute paths of
 * the files currently being expanded (root template -> ... -> this content); it
 * powers cycle detection (a path that reappears on the stack is a cycle) and the
 * depth cap. Returns `content` with all directives — at every nesting level —
 * replaced by their recursively expanded file contents.
 */
async function resolveIncludes(
	content: string,
	baseDir: string,
	resolvedBase: string,
	stack: readonly string[],
): Promise<string> {
	const matches = Array.from(content.matchAll(INCLUDE_REGEX));
	if (matches.length === 0) {
		return content;
	}

	if (stack.length >= MAX_INCLUDE_DEPTH) {
		throw new PentestError(
			`@include nesting exceeded depth cap (${MAX_INCLUDE_DEPTH})`,
			"prompt",
			false,
			{ depth: stack.length, stack: [...stack] },
		);
	}

	const segments = await Promise.all(
		matches.map(async (match) => {
			const placeholder = match[0] ?? "";
			const rawPath = match[1] ?? "";
			const start = match.index ?? 0;
			const includePath = path.resolve(baseDir, rawPath);

			// Path-traversal guard — enforced at EVERY level, not just the top.
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

			// Cycle guard — a file that transitively includes itself would loop.
			if (stack.includes(includePath)) {
				throw new PentestError(
					`Cyclic @include detected: ${rawPath}`,
					"prompt",
					false,
					{
						includePath,
						stack: [...stack, includePath],
					},
				);
			}

			const fileContent = await fs.readFile(includePath, "utf8");
			const expanded = await resolveIncludes(
				fileContent,
				baseDir,
				resolvedBase,
				[...stack, includePath],
			);
			return { start, end: start + placeholder.length, text: expanded };
		}),
	);

	// Splice expanded content back in by source offset. Offset splicing (vs
	// String.replace) inserts file contents verbatim — no `$&`/`$1` substitution
	// pattern interpretation — and keeps top-level output byte-identical to the
	// prior single-pass code for prompts that have no nested includes.
	let result = "";
	let lastIndex = 0;
	for (const segment of segments) {
		result += content.slice(lastIndex, segment.start) + segment.text;
		lastIndex = segment.end;
	}
	result += content.slice(lastIndex);
	return result;
}
