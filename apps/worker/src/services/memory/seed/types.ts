// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Types for the RAG seed subsystem (attack-technique exemplars).
 *
 * A "seed" pre-populates the shared, cross-tenant `global_pool` (T2) with
 * PUBLIC-research attack-technique exemplars — never client data. Each exemplar
 * is stored exactly like a pooled finding (task 014): two dense vectors (a
 * verbalized text doc + the PoC-skeleton code) plus a structured payload. Seeds
 * carry `sourceTenant: null` (public provenance) so they SIDESTEP the
 * cross-tenant pooling consent gate — there is no tenant to consent, the data is
 * already public.
 *
 * The three novelty tiers reflect provenance quality, not exploit power:
 *   - `known`    — mechanically parsed from a public catalogue (CAPEC/STIX);
 *   - `novel`    — LLM-distilled from a public write-up (structured fields ONLY,
 *                  never verbatim source text — a licensing invariant);
 *   - `flagship` — hand-encoded from a landmark technique (this repo's manifest).
 */

import type { GlobalPoolWriter, Vector } from "../pooling/index.js";

export type { GlobalPoolWriter, Vector };

/** Provenance quality of a seed exemplar (see file header). */
export type NoveltyTier = "known" | "novel" | "flagship";

/**
 * Where a seed came from. `source` is the human-readable origin (e.g. "MITRE
 * CAPEC", "PortSwigger Research"); `url` is the canonical public reference kept
 * for attribution; `date` is an optional publication date (ISO or free-form).
 * NOTE: this is provenance metadata, distinct from an exemplar's data-flow
 * `source` (the taint origin).
 */
export interface SeedProvenance {
	readonly source: string;
	readonly url?: string;
	readonly date?: string;
}

/**
 * One attack-technique exemplar, the seed unit. Mirrors the Vul-RAG verbalized
 * shape (task 011) but describes a TECHNIQUE class rather than one finding:
 *   - `preconditions` — what must hold for the technique to apply;
 *   - `rootCause`     — the underlying weakness the technique exploits;
 *   - `source`/`sink` — the abstract taint data-flow (attacker input -> danger);
 *   - `probeSignal`   — the observable that confirms the technique is present;
 *   - `pocSkeleton`   — a minimal, generic proof-of-concept sketch (Vector B).
 */
export interface SeedExemplar {
	readonly technique: string;
	readonly aliases?: readonly string[];
	readonly preconditions: string;
	readonly rootCause: string;
	/** Data-flow taint source (attacker-controlled input). */
	readonly source: string;
	/** Data-flow taint sink (the dangerous operation). */
	readonly sink: string;
	readonly probeSignal: string;
	readonly pocSkeleton: string;
	readonly cwe?: string;
	readonly capecId?: string;
	readonly tags: readonly string[];
	readonly noveltyTier: NoveltyTier;
	readonly provenance: SeedProvenance;
}

/**
 * The verbalized representation of a seed exemplar, ready to embed. Mirrors task
 * 011's `VerbalizedFinding`: `text` is Vector A (labeled doc + metadata prefix),
 * `codeText` is Vector B (the PoC skeleton). Pure — no scrub needed: seeds are
 * hand/machine-authored public research and carry no secrets or PII.
 */
export interface VerbalizedSeed {
	/** One-line contextual metadata prefix (CWE / CAPEC / tier). */
	readonly metadataPrefix: string;
	/** The labeled doc body (without the prefix). */
	readonly doc: string;
	/** Vector A text: `metadataPrefix` + blank line + `doc`. */
	readonly text: string;
	/** Vector B text: the PoC skeleton (empty string when absent). */
	readonly codeText: string;
}
