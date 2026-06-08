// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Module root for the findings MAPPING layer (split out of the former 322-line
 * `mapping.ts`, which exceeded the 300-line cap — finding F4). Public surface:
 *
 *   - `toFindingRecord` / `toFindingRecords` — map normalized vulns → §6.1 records
 *     (`record.ts`). Back-compat: an optional options arg threads the analyzed-
 *     source root for cite-line verification; existing callers pass nothing.
 *   - `deriveConfidence` / `deriveSeverity` — disposition-decoupled scoring (T1,
 *     `scoring.ts`); consumed by Tasks 002/003.
 *   - `resolveCwe` — per-finding, mechanism-aware CWE (T4, `cwe-map.ts`).
 *   - `verifyLocation` — cite-line verifier (T5, `verify-location.ts`).
 *
 * `mapping.ts` re-exports this root so `import { … } from "./mapping.js"` is
 * unchanged for every existing consumer (`gating.ts`, `services/measurement`).
 */

export { type CweResolution, resolveCwe } from './cwe-map.js';
export {
  type ToFindingRecordOptions,
  toFindingRecord,
  toFindingRecords,
} from './record.js';
export { deriveConfidence, deriveSeverity, type ScoringAxes } from './scoring.js';
export { verifyLocation } from './verify-location.js';
