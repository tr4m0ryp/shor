// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * RAG seed subsystem — public surface.
 *
 * Pre-seeds the shared global-pool exemplar tier (T2) with PUBLIC attack-technique
 * exemplars (`sourceTenant: null`). Three provenance tiers feed one ingest path:
 *   - `flagship` — the committed hand-encoded {@link flagshipManifest};
 *   - `known`    — {@link parseCapecStix} over a MITRE CAPEC STIX bundle;
 *   - `novel`    — {@link distillWriteup} over a public write-up (LLM, injected).
 * All flow through {@link seedGlobalPool}. The CLI (`cli.ts`) is the runnable
 * wiring; it is default-off behind `SHOR_SEED_GLOBAL`.
 */

export { parseCapecStix } from "./capec/parse.js";
export {
	type DistillDeps,
	distillWriteup,
	type StructuredRunner,
} from "./distill/distill.js";
export {
	type SeedIngestDeps,
	type SeedIngestResult,
	type SeedSkipReason,
	seedGlobalPool,
	seedKey,
} from "./ingest.js";
export { FLAGSHIP_SEEDS, flagshipManifest } from "./manifest.js";
export type {
	GlobalPoolWriter,
	NoveltyTier,
	SeedExemplar,
	SeedProvenance,
	Vector,
	VerbalizedSeed,
} from "./types.js";
export {
	SEED_DOC_LABELS,
	seedMetadataPrefix,
	verbalizeSeed,
} from "./verbalize.js";
