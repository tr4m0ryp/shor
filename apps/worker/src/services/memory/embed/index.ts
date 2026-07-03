// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Embed/rerank client — public surface (task 002).
 *
 * Downstream RAG tasks (011/012/013) import from here only:
 *   import { createEmbedClient } from "../memory/embed/index.js";
 *   const embedder = createEmbedClient(); // no-op unless SHOR_EMBED_URL set
 */

export type {
	EmbedClient,
	EmbedClientConfig,
	EmbedOptions,
	EmbedResult,
	EmbedSpace,
	RerankHit,
	RerankOptions,
} from "./types.js";
export {
	createEmbedClient,
	EmbedError,
	MAX_RERANK,
	readEmbedConfig,
} from "./client.js";
