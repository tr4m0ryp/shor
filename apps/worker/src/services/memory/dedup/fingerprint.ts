// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Deterministic `fpv1` fingerprint — the dedup fast-path (spec T6, R10;
 * SARIF `partialFingerprints` in spirit).
 *
 * A cross-scan-stable, line-drift-tolerant key over a finding's ROOT CAUSE:
 * the file, CWE, category, semantic sink/route anchor, and a rolling hash of
 * the normalized vulnerable code region. Two scans of the same repo produce the
 * SAME `fpv1` for the same bug even when line numbers shift, blank lines are
 * added, or comments/indentation change — so an exact match is a confident
 * "already known", merge, and stop WITHOUT paying for an embedding.
 *
 * Distinct from the §6.1 `finding.fingerprint` (upsert-by-fingerprint, which is
 * NOT drift-tolerant): `fpv1` is additive dedup identity, computed here.
 *
 * Also home to the STRUCTURAL GATE: two findings may only merge when they share
 * a structural anchor (file / CWE family / endpoint / component). The embedding
 * similarity never merges across a gate mismatch — that would fold a real new
 * bug into an unrelated cluster (a security-critical false negative).
 */

import { createHash } from "node:crypto";
import type { FindingLike } from "../schema/index.js";
import { extractMetadata } from "../schema/index.js";
import type { StructuralKey } from "./types.js";

/** Lowercase, POSIX-slash, strip a trailing line suffix from a file path. */
function normalizePath(file: string | null | undefined): string | null {
	if (typeof file !== "string" || file.trim() === "") return null;
	return file.replace(/\\/g, "/").trim().toLowerCase();
}

/** Just the basename of a normalized path (the loosest file anchor). */
function baseName(file: string | null): string | null {
	if (!file) return null;
	const parts = file.split("/").filter((p) => p.length > 0);
	return parts.length > 0 ? (parts[parts.length - 1] as string) : null;
}

/** `CWE-639` -> `cwe-639`; anything non-CWE-shaped passes through lowercased. */
function normalizeCwe(cwe: string | null | undefined): string | null {
	if (typeof cwe !== "string" || cwe.trim() === "") return null;
	const m = cwe.trim().toUpperCase().match(/CWE[-\s]?(\d+)/);
	return m ? `cwe-${m[1]}` : cwe.trim().toLowerCase();
}

/**
 * The CWE "family" is just the numeric id here — we deliberately do NOT collapse
 * across ids (CWE-862 vs CWE-306 are different weaknesses). Kept as a distinct
 * field so the gate can be relaxed later without touching call-sites.
 */
function cweFamilyOf(cwe: string | null): string | null {
	return cwe;
}

/** Collapse whitespace + lowercase a short structural token. */
function normalizeToken(value: string | null | undefined): string | null {
	if (typeof value !== "string" || value.trim() === "") return null;
	return value.replace(/\s+/g, " ").trim().toLowerCase();
}

/**
 * Normalize a code region into a drift-tolerant token stream, then hash it —
 * the "rolling code-region hash". Strips line + block comments, collapses all
 * whitespace, and lowercases, so indentation / blank-line / line-number churn
 * does not change the fingerprint while the actual code tokens do.
 */
export function codeRegionHash(code: string | null | undefined): string | null {
	if (typeof code !== "string" || code.trim() === "") return null;
	const stripped = code
		.replace(/\/\*[\s\S]*?\*\//g, " ") // block comments
		.replace(/(^|[^:])\/\/[^\n]*/g, "$1 ") // line comments (keep url schemes)
		.replace(/#[^\n]*/g, " ") // hash comments (py/sh/yaml)
		.replace(/\s+/g, " ")
		.trim()
		.toLowerCase();
	if (stripped === "") return null;
	return createHash("sha1").update(stripped).digest("hex").slice(0, 16);
}

/** Extract the structural axes the gate compares. */
export function structuralKeyOf(finding: FindingLike): StructuralKey {
	const meta = extractMetadata(finding);
	const filePath = normalizePath(finding.vulnerable_code_location?.file);
	const cwe = normalizeCwe(meta.cwe);
	return {
		fileBase: baseName(filePath),
		cwe,
		cweFamily: cweFamilyOf(cwe),
		endpoint: normalizeToken(meta.route),
		component: normalizeToken(meta.componentVer),
		category: normalizeToken(meta.vulnClass),
	};
}

/**
 * Compute the deterministic `fpv1` for a finding. Order-stable, total (a
 * near-empty finding still yields a value), and independent of line numbers.
 * The sink/route anchor + code-region hash carry the "same root cause" signal;
 * file + CWE + category disambiguate co-located but distinct weaknesses.
 */
export function computeFpv1(finding: FindingLike): string {
	const s = structuralKeyOf(finding);
	const anchor =
		normalizeToken(extractMetadata(finding).sink) ?? s.endpoint ?? "-";
	const code =
		codeRegionHash(
			pickCode(finding),
		) ?? "-";
	const parts = [
		s.fileBase ?? "-",
		s.cwe ?? "-",
		s.category ?? "-",
		anchor,
		code,
	];
	const digest = createHash("sha1").update(parts.join("|")).digest("hex");
	return `fpv1:${digest.slice(0, 16)}`;
}

/** Pull a raw code snippet off a finding (mirrors verbalize's key list). */
function pickCode(finding: FindingLike): string | null {
	for (const key of [
		"code_snippet",
		"snippet",
		"vulnerable_code",
		"code",
		"source_snippet",
	]) {
		const v = finding[key];
		if (typeof v === "string" && v.trim() !== "") return v;
	}
	return null;
}

/**
 * The STRUCTURAL GATE. Two findings may merge only when they share at least one
 * structural anchor: the same file, the same endpoint, the same component, or
 * the same CWE family. Category alone is NOT an anchor (too coarse — it would
 * merge every "authz" finding). Absent-on-both axes never count as agreement.
 */
export function structuralAgree(a: StructuralKey, b: StructuralKey): boolean {
	const eq = (x: string | null, y: string | null): boolean =>
		x !== null && y !== null && x === y;
	return (
		eq(a.fileBase, b.fileBase) ||
		eq(a.endpoint, b.endpoint) ||
		eq(a.component, b.component) ||
		eq(a.cweFamily, b.cweFamily)
	);
}
