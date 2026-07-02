// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Injectable interfaces for extending the pentest pipeline.
 *
 * All interfaces have default no-op implementations.
 * Consumers can provide alternate implementations via the DI container.
 */

export type { CheckpointProvider } from "./checkpoint-provider.js";
export { NoOpCheckpointProvider } from "./checkpoint-provider.js";
export type { FindingsProvider } from "./findings-provider.js";
export { NoOpFindingsProvider } from "./findings-provider.js";
