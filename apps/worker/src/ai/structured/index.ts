// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
