// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Typed repositories over the Cloud SQL pool — public surface.
 *
 * Every method uses parameterized queries and (for non-root entities) enforces
 * `tenantId` scoping in its signature (ADR-044). Re-exported here so dependent
 * Phase 2-5 tasks can `import { scanRepo, findingRepo } from ".../repositories"`.
 */

export { attackSurfaceRepo } from './attack-surface.js';
export { codebaseVersionRepo } from './codebase-version.js';
export { findingRepo } from './finding.js';
export { launchTokenRepo } from './launch-token.js';
export { projectRepo } from './project.js';
export { providerKeyRepo } from './provider-key.js';
export type {
  AttackSurfaceRow,
  CodebaseVersionRow,
  FindingRow,
  ProjectRow,
  ProviderKeyRow,
  ScanRow,
  TenantRow,
  UserRow,
} from './rows.js';
export { scanRepo } from './scan.js';
export { tenantRepo } from './tenant.js';
export { userRepo } from './user.js';
