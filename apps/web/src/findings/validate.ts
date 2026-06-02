/**
 * Finding schema validation (LAUNCH-SPEC §6.1, ADR-030).
 *
 * The worker emits findings in storron's `findings/types.ts` shape extended
 * with the fingerprint block. Before persistence the sink validates each record
 * against §6.1 so malformed emitter output never reaches the datastore. The
 * fingerprint block itself is recomputed by the sink, so it is NOT required on
 * input here.
 */

import {
  FINDING_SEVERITIES,
  type FindingConfidence,
  type FindingRecord,
  type FindingSeverity,
} from '../domain/types.js';

const CONFIDENCES: readonly FindingConfidence[] = ['confirmed', 'firm', 'tentative'] as const;

/** A validation failure: which finding (by index) and what was wrong. */
export interface FindingValidationIssue {
  readonly index: number;
  readonly field: string;
  readonly message: string;
}

export class FindingValidationError extends Error {
  constructor(public readonly issues: readonly FindingValidationIssue[]) {
    super(`finding validation failed: ${issues.length} issue(s)`);
    this.name = 'FindingValidationError';
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === 'string');
}

/**
 * Validate one candidate against §6.1. Returns the issues found (empty = valid).
 * `index` is the position in the emitter batch, surfaced back to the caller.
 */
export function validateFinding(candidate: unknown, index: number): FindingValidationIssue[] {
  const issues: FindingValidationIssue[] = [];
  const push = (field: string, message: string): void => {
    issues.push({ index, field, message });
  };

  if (!isObject(candidate)) {
    return [{ index, field: '<root>', message: 'finding must be an object' }];
  }

  const requiredStrings: readonly (keyof FindingRecord)[] = [
    'id',
    'category',
    'cwe',
    'owasp_category',
    'evidence',
    'safe_poc',
    'missing_defense',
    'remediation',
  ];
  for (const key of requiredStrings) {
    if (typeof candidate[key] !== 'string' || (candidate[key] as string).length === 0) {
      push(String(key), 'required non-empty string');
    }
  }

  const sev = candidate.severity;
  if (typeof sev !== 'string' || !FINDING_SEVERITIES.includes(sev as FindingSeverity)) {
    push('severity', `must be one of ${FINDING_SEVERITIES.join('|')}`);
  }

  const conf = candidate.confidence;
  if (typeof conf !== 'string' || !CONFIDENCES.includes(conf as FindingConfidence)) {
    push('confidence', `must be one of ${CONFIDENCES.join('|')}`);
  }

  if (!isStringArray(candidate.repro_steps)) {
    push('repro_steps', 'must be an array of strings');
  }

  const loc = candidate.vulnerable_code_location;
  if (!isObject(loc)) {
    push('vulnerable_code_location', 'must be an object { file, line }');
  } else {
    if (typeof loc.file !== 'string' || loc.file.length === 0) {
      push('vulnerable_code_location.file', 'required non-empty string');
    }
    if (typeof loc.line !== 'number' || !Number.isFinite(loc.line)) {
      push('vulnerable_code_location.line', 'required number');
    }
  }

  return issues;
}

/**
 * Validate a batch and throw `FindingValidationError` with all issues if any
 * record is invalid. On success the records are structurally §6.1-conformant
 * (sans the fingerprint block, which the sink computes).
 */
export function assertValidFindings(candidates: readonly unknown[]): void {
  const issues = candidates.flatMap((c, i) => validateFinding(c, i));
  if (issues.length > 0) {
    throw new FindingValidationError(issues);
  }
}
