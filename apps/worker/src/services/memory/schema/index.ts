// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Verbalized finding schema — public surface (task 011, spec T3/R3).
 *
 * The write path (`../write/persist.ts`) and later retrieval/dedup tasks import
 * the representation from here:
 *   import { verbalize } from "../schema/index.js";
 */

export type {
	CodeChunkOptions,
	FindingLike,
	FindingMetadata,
	VerbalizedFinding,
} from "./types.js";
export {
	DOC_LABELS,
	extractCodeBlock,
	extractMetadata,
	lateChunkCode,
	metadataPrefix,
	verbalize,
} from "./verbalize.js";
