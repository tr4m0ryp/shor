// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

// Tiered, truncation-aware structured-output repair. `local.ts` = pure JSON
// primitives; `ladder.ts` = the ordered recovery ladder consumed by
// `runStructured` (see ../run.ts).

export {
  attemptLocalRepair,
  buildReaskInstruction,
  isTruncationStop,
  type LocalRepairInput,
  type LocalRepairOutcome,
  type RepairMeta,
  type RepairMethod,
  type StructuredValidator,
} from './ladder.js';
export {
  coerceJson,
  extractJsonCandidate,
  type JsonCandidate,
  salvageArrayPrefix,
  scanBalanced,
  tryParse,
} from './local.js';
