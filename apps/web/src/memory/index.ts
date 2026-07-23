// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Memory store HTTP seam — public surface. The worker's two-tier RAG reaches
 * the pgvector store through `handleMemoryRequest` (see `./sink.js`).
 */

export { handleMemoryRequest } from './sink.js';
