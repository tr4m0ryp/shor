/**
 * Shor cloud client wrappers — public surface.
 *
 * All clients are lazy: importing this module performs no I/O and needs no live
 * GCP/Temporal credentials.
 */

export * as identity from './identity.js';
export {
  TokenVerificationError,
  type VerifiedPrincipal,
  verifyIdToken,
} from './identity.js';
export * as pg from './pg.js';
export { closePool, getPool, query, withTransaction } from './pg.js';
export * as secrets from './secret-manager.js';
export {
  deleteSecret,
  getSecret,
  secretIdFromRef,
  secretRef,
  setSecret,
} from './secret-manager.js';
export * as storage from './storage.js';
export {
  deleteObject,
  getObject,
  gsUri,
  listObjects,
  objectPrefix,
  putObject,
  signedReadUrl,
} from './storage.js';
export * as temporal from './temporal.js';
export {
  getTemporalClient,
  resetTemporalClient,
  scanTaskQueue,
  scanWorkflowId,
} from './temporal.js';
