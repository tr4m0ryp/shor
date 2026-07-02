// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
