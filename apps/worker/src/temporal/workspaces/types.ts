// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
