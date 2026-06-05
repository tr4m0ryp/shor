// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Finding grader — STABLE seam.
 *
 * Assigns a quality/severity grade to each emitted finding. DEFAULT: identity —
 * returns the findings unchanged so today's emitted set is unchanged. Task 015
 * fills `gradeFindings` with the grader.
 */

import type { FindingRecord } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";

/** Options threaded to the grader (deliverables location + logger). */
export interface GradeOptions {
	deliverablesPath: string;
	logger: ActivityLogger;
}

/**
 * Grade findings. DEFAULT: identity (returns `findings` unchanged). Task 015
 * fills this.
 */
export function gradeFindings(
	findings: FindingRecord[],
	opts: GradeOptions,
): FindingRecord[] {
	void opts;
	return findings;
}
