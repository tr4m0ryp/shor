/**
 * SARIF 2.1.0 export view (LAUNCH-SPEC §6.1 storage-vs-export, ADR-033).
 *
 * Storage stays Postgres JSONB in storron's §6.1 shape; SARIF is an EXPORT view
 * only, emitted by `toSarif(findings)` and served at `GET /export/sarif?scan=`
 * for GitHub code-scanning / CI ingestion. We map:
 *   - severity   → result.level + `security-severity` property,
 *   - cwe        → reportingDescriptor.relationships (taxa) + a tag,
 *   - location   → physicalLocation (code) or a logical message (DAST),
 *   - partialFingerprints → result.partialFingerprints (verbatim),
 *   - fingerprint → result.fingerprints["aegis/v1"].
 *
 * The schema is intentionally a minimal-but-valid SARIF log: a single run with
 * one tool driver, deduplicated rules, and one result per finding.
 */

import type { Finding, FindingRecord, FindingSeverity } from '../domain/types.js';

const SARIF_VERSION = '2.1.0';
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const TOOL_NAME = 'Aegis';
const TOOL_VERSION = '1.0.0';
const INFORMATION_URI = 'https://github.com/aegis-security';

/** SARIF result severity level. `info`/`low` map to note, `medium` to warning. */
type SarifLevel = 'none' | 'note' | 'warning' | 'error';

/** Minimal structural SARIF log shape (the export contract; not exhaustive). */
export interface SarifLog {
  readonly $schema: string;
  readonly version: string;
  readonly runs: SarifRun[];
}

interface SarifRun {
  readonly tool: { readonly driver: SarifDriver };
  readonly results: SarifResult[];
}

interface SarifDriver {
  readonly name: string;
  readonly version: string;
  readonly informationUri: string;
  readonly rules: SarifRule[];
}

interface SarifRule {
  readonly id: string;
  readonly name: string;
  readonly shortDescription: { readonly text: string };
  readonly fullDescription?: { readonly text: string };
  readonly helpUri?: string;
  readonly properties: { readonly tags: string[]; readonly 'security-severity'?: string };
}

interface SarifResult {
  readonly ruleId: string;
  readonly level: SarifLevel;
  readonly message: { readonly text: string };
  readonly locations: SarifLocation[];
  readonly partialFingerprints: Record<string, string>;
  readonly fingerprints: Record<string, string>;
  readonly properties: Record<string, unknown>;
}

interface SarifLocation {
  readonly physicalLocation: {
    readonly artifactLocation: { readonly uri: string };
    readonly region?: { readonly startLine: number };
  };
}

/** GitHub-style numeric `security-severity` (CVSS-ish) per severity bucket. */
const SECURITY_SEVERITY: Readonly<Record<FindingSeverity, string>> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '0.0',
};

const LEVEL: Readonly<Record<FindingSeverity, SarifLevel>> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** Stable SARIF rule id for a finding — its CWE (the diff/grouping axis). */
function ruleIdFor(record: FindingRecord): string {
  return record.cwe || record.category || 'aegis-finding';
}

function isPersistedFinding(value: Finding | FindingRecord): value is Finding {
  const data = (value as { data?: unknown }).data;
  return typeof data === 'object' && data !== null && typeof (value as Finding).scanId === 'string';
}

/** Extract the §6.1 record from either a persisted `Finding` or a bare record. */
function toRecord(finding: Finding | FindingRecord): FindingRecord {
  return isPersistedFinding(finding) ? finding.data : finding;
}

/** A CWE id like `CWE-89` → its taxonomy help URI. */
function cweHelpUri(cwe: string): string | undefined {
  const m = /^CWE-(\d+)$/i.exec(cwe.trim());
  return m ? `https://cwe.mitre.org/data/definitions/${m[1]}.html` : undefined;
}

function buildRule(record: FindingRecord): SarifRule {
  const severity = record.severity;
  const helpUri = cweHelpUri(record.cwe);
  const rule: SarifRule = {
    id: ruleIdFor(record),
    name: record.category || record.cwe,
    shortDescription: { text: record.category || record.cwe },
    fullDescription: { text: record.missing_defense || record.remediation || record.category },
    properties: {
      tags: ['security', record.owasp_category, record.cwe].filter(Boolean),
      'security-severity': SECURITY_SEVERITY[severity] ?? SECURITY_SEVERITY.info,
    },
    ...(helpUri ? { helpUri } : {}),
  };
  return rule;
}

function buildLocation(record: FindingRecord): SarifLocation {
  const loc = record.vulnerable_code_location;
  const uri = loc?.file ? loc.file.replace(/\\/g, '/') : 'unknown';
  const line = Number.isFinite(loc?.line) && loc.line > 0 ? loc.line : undefined;
  return {
    physicalLocation: {
      artifactLocation: { uri },
      ...(line !== undefined ? { region: { startLine: line } } : {}),
    },
  };
}

function buildResult(record: FindingRecord): SarifResult {
  const severity = record.severity;
  const partial =
    record.partialFingerprints && typeof record.partialFingerprints === 'object' ? record.partialFingerprints : {};
  return {
    ruleId: ruleIdFor(record),
    level: LEVEL[severity] ?? 'note',
    message: { text: record.evidence || record.category || record.cwe },
    locations: [buildLocation(record)],
    partialFingerprints: partial,
    fingerprints: record.fingerprint ? { 'aegis/v1': record.fingerprint } : {},
    properties: {
      severity,
      confidence: record.confidence,
      owasp: record.owasp_category,
      status: record.status,
      remediation: record.remediation,
    },
  };
}

/**
 * Convert a batch of findings (persisted rows or bare §6.1 records) into a valid
 * SARIF 2.1.0 log: one run, deduplicated rules keyed by CWE, one result each.
 */
export function toSarif(findings: readonly (Finding | FindingRecord)[]): SarifLog {
  const records = findings.map(toRecord);

  const rulesById = new Map<string, SarifRule>();
  for (const record of records) {
    const id = ruleIdFor(record);
    if (!rulesById.has(id)) rulesById.set(id, buildRule(record));
  }

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: INFORMATION_URI,
            rules: [...rulesById.values()],
          },
        },
        results: records.map(buildResult),
      },
    ],
  };
}
