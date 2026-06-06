// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Shared path helpers for the agent validators. Deliverables live under
 * `<repoPath>/.storron/deliverables[/...]` and scratch work under
 * `<repoPath>/.storron/scratchpad`; both pre-recon and recon post-checks need to
 * resolve those from the deliverables dir they're handed.
 */

import { path } from "zx";

/**
 * Derive the cloned-repo root from a deliverables directory. The repo root is
 * the parent of the nearest `.storron` ancestor; falls back to two levels up
 * (the default `.storron/deliverables` depth) when no `.storron` segment exists.
 */
export function repoRootFromDeliverables(sourceDir: string): string {
	const parts = sourceDir.split(path.sep);
	const idx = parts.lastIndexOf(".storron");
	if (idx > 0) return parts.slice(0, idx).join(path.sep) || path.sep;
	return path.resolve(sourceDir, "..", "..");
}

/** The per-run scratchpad dir (`<repo>/.storron/scratchpad`) siblings the deliverables. */
export function scratchpadDir(sourceDir: string): string {
	return path.join(repoRootFromDeliverables(sourceDir), ".storron", "scratchpad");
}
