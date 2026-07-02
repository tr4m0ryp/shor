#!/usr/bin/env node

// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import dotenv from "dotenv";
import { run } from "./worker/index.js";

export * from "./worker/index.js";

dotenv.config();

run().catch((err) => {
	console.error("Worker failed:", err);
	process.exit(1);
});
