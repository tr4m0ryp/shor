// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Types for the verbalized finding representation (spec T3, R3 / Vul-RAG +
 * contextual retrieval).
 *
 * A finding is stored for retrieval as TWO embedding inputs plus structured
 * columns:
 *   - Vector A ("text"): a labeled verbalized doc (VULNERABILITY / ENDPOINT /
 *     DATA FLOW / WHAT THE CODE DOES / ROOT CAUSE / IMPACT / REMEDIATION),
 *     prefixed with a contextual metadata line (CWE / route / severity). Never
 *     raw JSON — retrieval is on semantics.
 *   - Vector B ("code"): the minimal vulnerable code block, late-chunked so the
 *     immediately-surrounding context survives.
 * The structured `metadata` feeds the SQL pre-filter + exact-identifier BM25.
 */

/**
 * The finding fields the verbalizer reads. A worker `FindingRecord`
 * (`job/findings/types.ts`) is structurally assignable to this (its named
 * fields are compatible and it carries an index signature); tests can pass a
 * plain object. Every named field is optional so a partial record still
 * verbalizes — missing fields render as an explicit `n/a` label, never a throw.
 */
export interface FindingLike {
	readonly title?: string;
	readonly category?: string;
	readonly vuln_class?: string;
	readonly cwe?: string;
	readonly owasp_category?: string;
	readonly severity?: string;
	readonly confidence?: string;
	readonly evidence?: string;
	readonly missing_defense?: string;
	readonly remediation?: string;
	readonly validation_note?: string;
	readonly vulnerable_code_location?: { file?: string; line?: number };
	readonly fingerprint?: string;
	readonly disposition?: string;
	readonly oracle_disposition?: string;
	readonly premise_valid?: boolean;
	readonly in_scope?: boolean;
	readonly [key: string]: unknown;
}

/**
 * Structured columns extracted from a finding for the SQL pre-filter +
 * exact-identifier BM25 (T3). Mirrors the persistable subset of the local-tier
 * `finding_embedding` row; `null` means "not present on this finding".
 */
export interface FindingMetadata {
	readonly cwe: string | null;
	readonly vulnClass: string | null;
	readonly severity: string | null;
	readonly route: string | null;
	readonly source: string | null;
	readonly sink: string | null;
	readonly componentVer: string | null;
	readonly confidence: string | null;
}

/** The full verbalized representation of a finding, ready to scrub + embed. */
export interface VerbalizedFinding {
	/** Contextual metadata prefix (CWE / route / severity), one line. */
	readonly metadataPrefix: string;
	/** The labeled verbalized doc body (without the prefix). */
	readonly doc: string;
	/**
	 * The text embedded as Vector A: `metadataPrefix` + blank line + `doc`. This
	 * is the exact string handed to the text embedder (after scrub).
	 */
	readonly text: string;
	/**
	 * The minimal vulnerable code block embedded as Vector B (after scrub), or
	 * `null` when the finding carries no code snippet — then no code vector is
	 * written.
	 */
	readonly codeBlock: string | null;
	/** Structured columns for the SQL pre-filter. */
	readonly metadata: FindingMetadata;
}

/** Options for the code-block late-chunker. */
export interface CodeChunkOptions {
	/** Soft character budget for the emitted block. Default 2000. */
	readonly maxChars?: number;
	/** A substring to keep centered (e.g. the sink token) when trimming. */
	readonly focusHint?: string | null;
}
