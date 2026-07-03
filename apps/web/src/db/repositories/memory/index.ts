// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Learning-memory repositories — public surface (engine-proof-and-memory P0/T1).
 *
 * The pgvector storage substrate for tasks 011-017: a project-local finding
 * embedding tier, a false-positive memory, the cross-tenant global pool, and a
 * public CVE registry. Backed by 0008_memory.sql. Consumers:
 *   `import { findingEmbeddingRepo, fpMemoryRepo, globalPoolRepo, cveRegistryRepo }
 *      from ".../db/repositories/memory/index.js";`
 */

export {
  EMBEDDING_DIM,
  type Embedding,
  parseHalfvec,
  type TenantScope,
  toHalfvec,
  withTenantContext,
} from './context.js';
export {
  type CveRegistryEntry,
  type CveRegistryInput,
  type CveRegistryMatch,
  cveRegistryRepo,
} from './cve-registry.js';
export {
  type FindingEmbedding,
  type FindingEmbeddingInput,
  type FindingEmbeddingMatch,
  findingEmbeddingRepo,
  type VecColumn,
} from './finding-embedding.js';
export {
  type FpMemory,
  type FpMemoryInput,
  type FpMemoryMatch,
  fpMemoryRepo,
} from './fp-memory.js';
export {
  type GlobalPoolInput,
  type GlobalPoolItem,
  type GlobalPoolKind,
  type GlobalPoolMatch,
  globalPoolRepo,
} from './global-pool.js';
