// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Shape of the workspace `session.json` file consumed by the resume loader.
 *
 * Mirrors the subset of fields written by the audit layer that the resume
 * path needs to decide which agents to skip and where to roll back to.
 */

import type { ResumeAttempt } from "../../../audit/metrics-tracker.js";

export interface SessionJson {
	session: {
		id: string;
		webUrl: string;
		repoPath?: string;
		originalWorkflowId?: string;
		resumeAttempts?: ResumeAttempt[];
	};
	metrics: {
		agents: Record<
			string,
			{
				status: "in-progress" | "success" | "failed";
				checkpoint?: string;
			}
		>;
	};
}
