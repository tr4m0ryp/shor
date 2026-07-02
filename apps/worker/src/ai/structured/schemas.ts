// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Structured-output schema + TS-type pairs.
 *
 * Each export is a small Zod object converted to a `JsonSchemaOutputFormat`
 * (for {@link runStructured}'s `schema` arg) plus the inferred TS type (for the
 * `T` of `runStructured<T>`). One Zod definition is the single source of truth
 * for both, so the wire schema and the static type can never drift.
 */

import type { JsonSchemaOutputFormat } from '@anthropic-ai/claude-agent-sdk';
import { z } from 'zod';

/**
 * Convert a Zod schema to the SDK's structured-output format.
 *
 * NOTE: the SDK's AJV validator expects draft-07; Zod defaults to draft-2020-12
 * which makes the SDK silently skip structured output. (Same gotcha handled in
 * `ai/queue-schemas.ts`.)
 */
function toOutputFormat(schema: z.ZodType): JsonSchemaOutputFormat {
  return {
    type: 'json_schema',
    schema: z.toJSONSchema(schema, { target: 'draft-07' }) as Record<string, unknown>,
  };
}

// === Screen verdict (adversarial refute/support pass over a candidate) ===

const ScreenVerdictDef = z.object({
  id: z.string(),
  verdict: z.enum(['refute', 'support', 'uncertain']),
  lens: z.string().optional(),
  reason: z.string(),
});
export type ScreenVerdict = z.infer<typeof ScreenVerdictDef>;
export const screenVerdictSchema: JsonSchemaOutputFormat = toOutputFormat(ScreenVerdictDef);

// === Dedup judgment (is this finding new or a duplicate of a cluster?) ===

const JudgmentDef = z.object({
  judgment: z.enum(['NEW', 'DUP_BETTER', 'DUP_SKIP']),
  cluster_id: z.string().optional(),
  reason: z.string(),
});
export type Judgment = z.infer<typeof JudgmentDef>;
export const judgmentSchema: JsonSchemaOutputFormat = toOutputFormat(JudgmentDef);

// === Finding grade (evidence-weighted scoring of a finding) ===

const FindingGradeDef = z.object({
  evidence_score: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  severity: z.string(),
  reachability: z.string(),
  novelty: z.string().optional(),
  confidence: z.string(),
});
export type FindingGrade = z.infer<typeof FindingGradeDef>;
export const findingGradeSchema: JsonSchemaOutputFormat = toOutputFormat(FindingGradeDef);

// === Oracle summary (replay disposition of an exploit attempt) ===

const OracleSummaryDef = z.object({
  id: z.string(),
  disposition: z.enum(['exploited', 'blocked', 'not_replayable']),
  signal: z.string(),
});
export type OracleSummary = z.infer<typeof OracleSummaryDef>;
export const oracleSummarySchema: JsonSchemaOutputFormat = toOutputFormat(OracleSummaryDef);
