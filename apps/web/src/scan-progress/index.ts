// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Live run-progress feed — public surface (ADR-051).
 *
 * The worker pushes phase/agent snapshots to `POST /scans/:id/progress`; the
 * dashboard polls `GET /scans/:id/progress` for the derived view. Wired from the
 * router.
 */

export { deriveProgressView, type ProgressView } from './derive.js';
export { getScanProgress, handleIngestProgress } from './handlers.js';
export { PIPELINE_PLAN, TOTAL_AGENTS } from './taxonomy.js';
