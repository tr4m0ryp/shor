// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
