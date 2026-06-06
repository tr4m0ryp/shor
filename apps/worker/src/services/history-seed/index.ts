// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Historical-exploit seed module (spec decision T4).
 *
 * Public surface: the `HistoricalSignal` type + caps, the defensive normalizer,
 * the `{{HISTORICAL_SEED}}` renderer, and the filesystem integration for the
 * `historical_signal.json` deliverable. The `git-security-history` skill writes
 * the file from the cloned repo's history; task 005's context-assembler reads it
 * back here and renders the seed. This module is LOCAL-ONLY — it makes no
 * network calls.
 */

import { fs, path } from "zx";

import { normalizeHistoricalSignal } from "./normalize.js";
import {
	EMPTY_HISTORICAL_SIGNAL,
	HISTORICAL_SIGNAL_FILENAME,
	type HistoricalSignal,
} from "./types.js";

export type {
	DepCve,
	HistCommit,
	HistoricalSignal,
	HotFile,
} from "./types.js";
export {
	EMPTY_HISTORICAL_SIGNAL,
	HISTORICAL_SIGNAL_FILENAME,
	HISTORY_CAPS,
} from "./types.js";
export {
	extractCveIds,
	normalizeHistoricalSignal,
	redactSecrets,
} from "./normalize.js";
export { renderHistoricalSeed } from "./render.js";

/**
 * Read + normalize `historical_signal.json` from `deliverablesDir`. Returns the
 * EMPTY signal when the file is absent or unparseable — a missing seed is a
 * normal "no prior signal mined" state, never an error.
 */
export async function readHistoricalSignal(
	deliverablesDir: string,
): Promise<HistoricalSignal> {
	const file = path.join(deliverablesDir, HISTORICAL_SIGNAL_FILENAME);
	try {
		if (!(await fs.pathExists(file))) return EMPTY_HISTORICAL_SIGNAL;
		return normalizeHistoricalSignal(JSON.parse(await fs.readFile(file, "utf8")));
	} catch {
		return EMPTY_HISTORICAL_SIGNAL;
	}
}

/**
 * Normalize `signal` and write it as `historical_signal.json` into
 * `deliverablesDir`. Ensures the directory exists; returns the written path.
 * This is the TS-side producer (the skill is the agent-side producer) — both
 * target the same pinned schema.
 */
export async function writeHistoricalSignal(
	deliverablesDir: string,
	signal: unknown,
): Promise<string> {
	const normalized = normalizeHistoricalSignal(signal);
	const file = path.join(deliverablesDir, HISTORICAL_SIGNAL_FILENAME);
	await fs.ensureDir(deliverablesDir);
	await fs.writeFile(file, `${JSON.stringify(normalized, null, 2)}\n`);
	return file;
}
