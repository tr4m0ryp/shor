// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/** Shape of the `session.json` file written into each workspace directory. */
export interface SessionJson {
	session: {
		id: string;
		webUrl: string;
		status: "in-progress" | "completed" | "failed";
		createdAt: string;
		completedAt?: string;
	};
}

/** Parsed, display-ready representation of a single workspace. */
export interface WorkspaceInfo {
	name: string;
	url: string;
	status: "in-progress" | "completed" | "failed";
	createdAt: Date;
	completedAt: Date | null;
}
