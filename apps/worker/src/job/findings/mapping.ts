// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Back-compat shim. The mapping layer used to live in this single 322-line file;
 * it exceeded the 300-line cap (finding F4) and was split into the `mapping/`
 * subtree (`record.ts`, `scoring.ts`, `cwe-map.ts`, `verify-location.ts`),
 * re-exported from `mapping/index.ts`.
 *
 * This module re-exports that public surface so every existing
 * `import { toFindingRecord, toFindingRecords } from "./mapping.js"` keeps
 * working unchanged (`gating.ts`, `services/measurement/load-findings.ts`).
 */

export {
  type CweResolution,
  deriveConfidence,
  deriveSeverity,
  resolveCwe,
  type ScoringAxes,
  type ToFindingRecordOptions,
  toFindingRecord,
  toFindingRecords,
  verifyLocation,
} from './mapping/index.js';
