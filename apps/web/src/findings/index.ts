/**
 * Findings datastore sink + diffs + SARIF export — public surface
 * (LAUNCH-SPEC §6, Phase 5, ADR-030/031/032/033).
 *
 * - fingerprint: the stable, scan-to-scan diff key + fuzzy partial fingerprints.
 * - validate:    §6.1 schema validation guarding the sink.
 * - sink:        `ingestFindings(...)` + `POST /scans/:id/findings` handler.
 * - diff:        `computeStatusTransitions(...)` → new|open|fixed|regressed.
 * - sarif:       `toSarif(...)` export view + `GET /export/sarif?scan=` handler.
 *
 * Re-exported here (NOT from the package root) so integration can wire it in.
 */

export {
  computeStatusTransitions,
  type DiffResult,
  diffFingerprints,
  type StatusTransition,
} from './diff.js';
export { handleSarifExport, type SarifExportResponse } from './export-handler.js';
export {
  computeFingerprint,
  computePartialFingerprints,
  normalizedEvidenceSignature,
  normalizedLocation,
  withFingerprints,
} from './fingerprint.js';
export { type SarifLog, toSarif } from './sarif.js';
export {
  handleIngestFindings,
  type IngestResult,
  ingestFindings,
  type SinkResponse,
  SinkScanNotFoundError,
} from './sink.js';
export {
  assertValidFindings,
  FindingValidationError,
  type FindingValidationIssue,
  validateFinding,
} from './validate.js';
