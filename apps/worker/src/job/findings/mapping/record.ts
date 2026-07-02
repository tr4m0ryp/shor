// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Map a normalized queue entry (+ optional exploitation evidence) into a
 * `FindingRecord` (LAUNCH-SPEC §6.1). Best-effort: a missing field becomes an
 * empty string / sentinel rather than dropping the finding — partial findings
 * beat none.
 *
 * `fingerprint` is the load-bearing stable diff key (ADR-031):
 *   sha256(category + cwe + normalized_location + evidence_signature).
 * The FORMULA is unchanged; T4 only feeds it a more accurate per-finding CWE.
 *
 * Scoring (confidence/severity), CWE resolution, and cite-line verification are
 * factored into sibling modules (`scoring.ts`, `cwe-map.ts`, `verify-location.ts`)
 * so this stays under the 300-line cap and each concern is independently testable.
 */

import { createHash } from 'node:crypto';
import { CATEGORY_META, explicitCwe, firstString } from '../category-meta.js';
import type {
  FindingRecord,
  FindingSeverity,
  NormalizedVuln,
  OracleDisposition,
  VulnerableCodeLocation,
} from '../types.js';
import { resolveCwe } from './cwe-map.js';
import { synthesizeValidationNote, synthTitle } from './prose.js';
import { deriveConfidence, deriveSeverity, type ScoringAxes } from './scoring.js';
import { verifyLocation } from './verify-location.js';

/** Options for {@link toFindingRecord} — all OPTIONAL (existing callers pass none). */
export interface ToFindingRecordOptions {
  /**
   * Filesystem root of the analyzed source (deliverables / repo path). When set,
   * the cite-line verifier checks the cited file:line and stamps
   * `location_verified`. Absent ⇒ verification is skipped (fail-open, today's behavior).
   */
  analyzedSourceRoot?: string;
}

/** Valid executable-oracle verdicts (T9), stamped on `raw` by the oracle phase. */
const ORACLE_DISPOSITIONS: ReadonlySet<string> = new Set<OracleDisposition>(['exploited', 'blocked', 'not_replayable']);

/** Type guard for the oracle verdict that `applyOracleDispositions` stashes on `raw`. */
function isOracleDisposition(v: unknown): v is OracleDisposition {
  return typeof v === 'string' && ORACLE_DISPOSITIONS.has(v);
}

/** Parse a `path/to/file.ts:123` token into `{ file, line }`. */
function parseLocation(loc: string): VulnerableCodeLocation {
  if (!loc) return { file: '', line: 0 };
  // Take the last `:<digits>` as the line; everything before is the file.
  const m = loc.match(/^(.*?):(\d+)(?:\D.*)?$/);
  if (m?.[1] !== undefined && m[2] !== undefined) {
    return { file: m[1].trim(), line: Number(m[2]) };
  }
  return { file: loc.trim(), line: 0 };
}

const SEVERITY_VALUES: readonly FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Parse a free-form severity string to the §6.1 enum, or null if unrecognized. */
function parseSeverity(value: string): FindingSeverity | null {
  const v = value.toLowerCase().trim();
  if ((SEVERITY_VALUES as string[]).includes(v)) return v as FindingSeverity;
  if (v === 'informational' || v === 'information') return 'info';
  return null;
}

/** Status for a freshly-emitted finding (always `new`; see below). */
function statusFor(): FindingRecord['status'] {
  // Every emitted finding is reported fresh; the web side computes the diff
  // lifecycle (open/fixed/regressed) against prior scans via the fingerprint.
  return 'new';
}

/**
 * Stable diff fingerprint (ADR-031): sha256 over category + cwe + normalized
 * location + an evidence signature. Lowercased + whitespace-collapsed so cosmetic
 * churn does not change the key.
 */
function computeFingerprint(
  category: string,
  cwe: string,
  location: VulnerableCodeLocation,
  evidenceSignature: string,
): string {
  const norm = (s: string): string => s.toLowerCase().replace(/\s+/g, ' ').trim();
  const locKey = `${norm(location.file)}:${location.line}`;
  const material = [norm(category), norm(cwe), locKey, norm(evidenceSignature)].join(' ');
  return createHash('sha256').update(material, 'utf8').digest('hex');
}

/** Map one normalized vuln into a §6.1 FindingRecord. */
export function toFindingRecord(vuln: NormalizedVuln, options?: ToFindingRecordOptions): FindingRecord {
  const meta = CATEGORY_META[vuln.category];
  const raw = vuln.raw;
  const oracleDisp = raw.oracle_disposition;

  // Per-finding CWE (T4): explicit → mechanism map → category default, EMITTED on
  // the record. The fingerprint, however, keeps consuming the LEGACY CWE
  // (`explicitCwe || defaultCwe`) so the ADR-031 diff key stays byte-stable across
  // this CWE enrichment — otherwise every reclassified finding would diff as
  // fixed+new instead of carrying over. Display gets the richer CWE; identity does not.
  const cweResolution = resolveCwe(raw, vuln.category, meta.defaultCwe);
  const cwe = cweResolution.cwe;
  const legacyCwe = explicitCwe(raw) || meta.defaultCwe;
  const locText = firstString(raw, meta.locationKeys) || firstString(raw, meta.endpointKeys);
  const location = parseLocation(locText);
  // Raw value drives the fingerprint (stable identity); the OUTPUT field gets a
  // non-empty fallback so the dashboard never shows a blank.
  const missingDefenseRaw = firstString(raw, meta.defenseKeys);
  const missingDefense = missingDefenseRaw || 'Not specified — see analysis deliverable';
  const witness = firstString(raw, meta.witnessKeys);

  // Evidence: prefer the live exploitation prose; fall back to a synthesized
  // summary from the queue entry so the field is never empty.
  const queueSummary = [
    firstString(raw, ['vulnerability_type']),
    firstString(raw, meta.endpointKeys),
    missingDefenseRaw,
    firstString(raw, ['notes']),
  ]
    .filter((s) => s !== '')
    .join(' — ');
  const evidence = vuln.evidenceText.trim() || queueSummary || `${vuln.category} finding — see analysis deliverable`;

  // Prefer an explicit severity from the queue (under any of the field names the
  // prompts use); otherwise infer from class + whether it was exploited. Never
  // blanket-default to "medium" — that masked the real distribution. Axes (T1)
  // only DOWN-adjust an `exploited` escalation; absent ⇒ identical to before.
  const explicitSeverity = parseSeverity(
    firstString(raw, [...meta.severityKeys, 'severity', 'severity_rating', 'risk', 'severity_band']),
  );
  // Build the axes object from ONLY the defined values (exactOptionalPropertyTypes):
  // an absent axis must stay absent, not become an explicit `undefined`.
  const axes: ScoringAxes = {
    ...(vuln.in_scope !== undefined && { in_scope: vuln.in_scope }),
    ...(vuln.premise_valid !== undefined && { premise_valid: vuln.premise_valid }),
  };
  const severity = deriveSeverity(vuln.category, vuln.disposition, explicitSeverity, axes);
  const confidence = deriveConfidence(firstString(raw, ['confidence']), vuln.disposition, axes);

  const reproStep = firstString(raw, meta.endpointKeys);
  const vulnerabilityType = firstString(raw, ['vulnerability_type']);
  const evidenceSignature = `${locText}|${missingDefenseRaw}|${vulnerabilityType}`;
  const fingerprint = computeFingerprint(
    vuln.category,
    legacyCwe,
    location,
    // signature: source/sink + missing defense gives a stable identity even
    // before live evidence exists (raw value — the display fallback must not
    // shift the fingerprint).
    evidenceSignature,
  );

  // Cite-line verification (T5): only runs when a source root is supplied. Returns
  // undefined on any inability to check (fail-open) — we omit the field then.
  const locationVerified = verifyLocation(location, options?.analyzedSourceRoot, evidenceSignature);

  const validation_note = synthesizeValidationNote(vuln.disposition, vuln.evidenceText);
  return {
    id: vuln.id,
    title: synthTitle(vuln.category, vulnerabilityType),
    category: vuln.category,
    cwe,
    owasp_category: meta.owasp,
    severity,
    confidence,
    evidence,
    safe_poc: witness || 'See exploitation evidence deliverable',
    repro_steps: reproStep ? [reproStep] : [],
    vulnerable_code_location: location,
    missing_defense: missingDefense,
    remediation: missingDefenseRaw
      ? `Apply the missing defense: ${missingDefenseRaw}. See the attack-surface deliverable for the context-correct fix prompt.`
      : `Apply the context-correct ${vuln.category} defense; see the attack-surface deliverable for the fix prompt.`,
    status: statusFor(),
    fingerprint,
    partialFingerprints: {
      'locationCwe/v1': computeFingerprint(vuln.category, legacyCwe, location, ''),
    },
    validation_note,
    // Forward-compatible: keep raw queue fields + disposition for the sink.
    disposition: vuln.disposition,
    // Executable-oracle verdict (T9), when the oracle phase stamped one on `raw`.
    ...(isOracleDisposition(oracleDisp) && { oracle_disposition: oracleDisp }),
    // Evidence axes (T1) — only stamped when the upstream vuln carried them, so
    // records from callers that don't set axes are byte-identical to before.
    ...(vuln.in_scope !== undefined && { in_scope: vuln.in_scope }),
    ...(vuln.premise_valid !== undefined && { premise_valid: vuln.premise_valid }),
    ...(cweResolution.inferred && { cwe_inferred: true }),
    ...(locationVerified !== undefined && { location_verified: locationVerified }),
    // T3: the cited line genuinely contains the construct ⇒ the finding is
    // confirmed-in-code. Only ever stamp `true`; a false/unknown must not assert
    // "not in code" (it may just be an unreadable source root — fail open).
    ...(locationVerified === true && { code_confirmed: true }),
    vulnerability_type: vulnerabilityType,
    externally_exploitable: raw.externally_exploitable === true,
  };
}

/** Map a batch, skipping nothing (each entry yields one record). */
export function toFindingRecords(vulns: NormalizedVuln[], options?: ToFindingRecordOptions): FindingRecord[] {
  return vulns.map((v) => toFindingRecord(v, options));
}
