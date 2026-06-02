#!/usr/bin/env node

// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Workspace listing tool for Storron.
 *
 * Reads workspaces/ directories, parses session.json files, and displays
 * a formatted table of all workspaces with status and duration.
 *
 * Usage:
 *   node dist/temporal/workspaces.js
 *
 * Environment:
 *   WORKSPACES_DIR - Override workspaces directory (default: ./workspaces)
 */

import { listWorkspaces } from "./workspaces/index.js";

export * from "./workspaces/index.js";

listWorkspaces().catch((err) => {
	console.error("Error listing workspaces:", err);
	process.exit(1);
});
