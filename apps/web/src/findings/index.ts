/**
 * Findings datastore sink + SARIF export — public surface
 * (LAUNCH-SPEC §6, Phase 5, ADR-030/031/033).
 *
 * - fingerprint: the stable, scan-to-scan dedupe key + fuzzy partial fingerprints.
 * - validate:    §6.1 schema validation guarding the sink.
 * - sink:        `ingestFindings(...)` + `POST /scans/:id/findings` handler.
 * - sarif:       `toSarif(...)` export view + `GET /export/sarif?scan=` handler.
 *
 * Re-exported here (NOT from the package root) so integration can wire it in.
 */

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
  resolveSinkTenant,
  type SinkResponse,
  SinkScanNotFoundError,
} from './sink.js';
export {
  assertValidFindings,
  FindingValidationError,
  type FindingValidationIssue,
  validateFinding,
} from './validate.js';
