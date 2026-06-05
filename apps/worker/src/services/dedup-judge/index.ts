// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Finding de-duplication / clustering — STABLE seam.
 *
 * Clusters near-duplicate findings (same underlying weakness surfaced by
 * multiple agents/queues) into a single emitted record. DEFAULT: identity —
 * returns the findings unchanged so today's emitted set is byte-for-byte the
 * same. Task 014 fills `clusterFindings` with the dedup-judge.
 */

import type { FindingRecord } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";

/** Options threaded to the dedup judge (deliverables location + logger). */
export interface ClusterOptions {
	deliverablesPath: string;
	logger: ActivityLogger;
}

/**
 * Cluster duplicate findings. DEFAULT: identity (returns `findings` unchanged).
 * Task 014 fills this.
 */
export function clusterFindings(
	findings: FindingRecord[],
	opts: ClusterOptions,
): FindingRecord[] {
	void opts;
	return findings;
}
