// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
