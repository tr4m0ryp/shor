// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Learning-memory write path — public surface (task 011).
 *
 * The sink integration wires the two repositories (apps/web) into these ports:
 *   import { persistFinding, persistFindings } from "../memory/write/index.js";
 */

export type {
	FindingEmbeddingWriter,
	FpMemoryWriter,
	MemoryWriteContext,
	PersistDeps,
	PersistOutcome,
} from "./persist.js";
export {
	persistFinding,
	persistFindings,
	readMemoryWriteEnabled,
	refutationDecision,
} from "./persist.js";
