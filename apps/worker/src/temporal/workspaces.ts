#!/usr/bin/env node

// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
