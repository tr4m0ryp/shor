// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

// Structured-output helper: run a Claude agent in JSON-schema mode and get back
// a validated, typed object instead of prose.

export { parseOr, type RunStructuredArgs, runStructured, type StructuredResult } from './run.js';
export {
  type FindingGrade,
  findingGradeSchema,
  type Judgment,
  judgmentSchema,
  type OracleSummary,
  oracleSummarySchema,
  type ScreenVerdict,
  screenVerdictSchema,
} from './schemas.js';
