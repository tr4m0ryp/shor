/**
 * Live run-progress feed — public surface (ADR-051).
 *
 * The worker pushes phase/agent snapshots to `POST /scans/:id/progress`; the
 * dashboard polls `GET /scans/:id/progress` for the derived view. Wired from the
 * router.
 */

export { deriveProgressView, type ProgressView } from './derive.js';
export { getScanProgress, handleIngestProgress } from './handlers.js';
export { PIPELINE_PLAN, TOTAL_AGENTS } from './taxonomy.js';
