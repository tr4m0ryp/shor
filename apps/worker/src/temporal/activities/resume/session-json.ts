// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
