// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Seed labeled sets derived from the two validated scans (spec T15), the deliverable
 * that unblocks two downstream tasks:
 *   - task 008 calibrates proof-confidence on {@link SEED_CALIBRATION_EXAMPLES}
 *     (predicted probability -> observed TP/FP), via {@link toCalibrationSamples}.
 *   - task 013 F1-sweeps the dedup cosine threshold on {@link SEED_DEDUP_PAIRS}
 *     (labeled same/different finding pairs from the scan-0008 semantic dups).
 *
 * Pure data + trivial adapters. The miscalibration signal is deliberately encoded:
 * several `confirmed`/high-confidence examples are actually FALSE (god-mode /
 * mock-OIDC inflation), so a calibration fit has real slope to learn.
 */

import type { BenchmarkSource } from "./types.js";

/** One labeled finding for confidence calibration: predicted prob + TP/FP label. */
export interface CalibrationExample {
	readonly id: string;
	readonly source: BenchmarkSource;
	/** Categorical confidence the pipeline assigned. */
	readonly confidenceLabel: "confirmed" | "firm" | "tentative" | "unverified";
	/** Numeric prior from that label; task 008 re-fits the mapping. */
	readonly predicted: number;
	/** Ground truth: 1 = true positive, 0 = false positive. */
	readonly label: 0 | 1;
	readonly note: string;
}

/** A generic (predicted, label) sample a calibration routine consumes. */
export interface CalibrationSample {
	readonly predicted: number;
	readonly label: 0 | 1;
}

/**
 * Labeled calibration examples. TPs span confidences; the FPs are the analyst's
 * confirmed-but-wrong cases (god-mode-inflated BOLA, mock-OIDC, phantom
 * path-traversal) — high predicted probability, label 0 — so the curve is not flat.
 */
export const SEED_CALIBRATION_EXAMPLES: readonly CalibrationExample[] = [
	{ id: "cal-versions-anon", source: "scan-0007", confidenceLabel: "confirmed", predicted: 0.9, label: 1, note: "Versions [AllowAnonymous] — real critical." },
	{ id: "cal-effect-ssrf", source: "scan-0007", confidenceLabel: "confirmed", predicted: 0.9, label: 1, note: "EffectService SSRF — real." },
	{ id: "cal-committed-keys", source: "scan-0008", confidenceLabel: "confirmed", predicted: 0.9, label: 1, note: "Committed keys in appsettings.json — git-verified real." },
	{ id: "cal-invites-authz", source: "scan-0007", confidenceLabel: "firm", predicted: 0.6, label: 1, note: "InvitesController missing authz — real." },
	{ id: "cal-rubric-xss", source: "scan-0007", confidenceLabel: "firm", predicted: 0.6, label: 1, note: "rehypeRaw stored XSS — real." },
	{ id: "cal-toctou", source: "scan-0007", confidenceLabel: "tentative", predicted: 0.35, label: 1, note: "Lost-update race — real, lower impact." },
	{ id: "cal-user-enum", source: "scan-0007", confidenceLabel: "tentative", predicted: 0.35, label: 1, note: "User enumeration — real, low." },
	{ id: "cal-bola-godmode", source: "scan-0008", confidenceLabel: "confirmed", predicted: 0.9, label: 0, note: "UsersController BOLA 'confirmed' only via forged-JWT/god-mode — impact overstated." },
	{ id: "cal-impersonation-inflated", source: "scan-0008", confidenceLabel: "confirmed", predicted: 0.9, label: 0, note: "Impersonation 'confirmed impact' exercised our injected OIDC session." },
	{ id: "cal-mock-oidc-algnone", source: "scan-0007", confidenceLabel: "confirmed", predicted: 0.9, label: 0, note: "alg:none on the :8090 mock OIDC — out of scope, not the target." },
	{ id: "cal-path-traversal", source: "scan-0008", confidenceLabel: "firm", predicted: 0.6, label: 0, note: "DictionaryProvider->FileSystemProvider flow does not exist — false positive." },
	{ id: "cal-security-headers", source: "scan-0008", confidenceLabel: "firm", predicted: 0.6, label: 0, note: "Missing CSP/HSTS rated high — low defense-in-depth, over-rated." },
];

/** Adapt the calibration examples into generic (predicted, label) samples. */
export function toCalibrationSamples(
	examples: readonly CalibrationExample[] = SEED_CALIBRATION_EXAMPLES,
): CalibrationSample[] {
	return examples.map((e) => ({ predicted: e.predicted, label: e.label }));
}

/** Minimal per-finding features a dedup similarity function can key on. */
export interface DedupFeatures {
	readonly file: string;
	readonly cwe: string;
	readonly category: string;
}

/** A labeled pair of findings: should the dedup pass MERGE them? */
export interface DedupPair {
	readonly a: string;
	readonly b: string;
	/** True when the two findings are the SAME underlying vuln (should merge). */
	readonly same: boolean;
	readonly featuresA: DedupFeatures;
	readonly featuresB: DedupFeatures;
	readonly note: string;
}

const CTRL = "backend/UvA.Workflow.Api/Controllers";
const SVC = "backend/UvA.Workflow.Api/Services";

/**
 * Labeled dedup pairs from the scan-0008 semantic-duplicate clusters (same root
 * cause, different files/wordings) plus true-distinct pairs. Task 013 sweeps its
 * similarity threshold to maximize F1 against `same`.
 */
export const SEED_DEDUP_PAIRS: readonly DedupPair[] = [
	{
		a: "f-0008-52", b: "f-0008-55", same: true,
		featuresA: { file: `${SVC}/EffectService.cs`, cwe: "CWE-918", category: "ssrf" },
		featuresB: { file: `${SVC}/EffectService.cs`, cwe: "CWE-918", category: "ssrf" },
		note: "Same EffectService SSRF sink, two wordings.",
	},
	{
		a: "f-0008-49", b: "f-0008-50", same: true,
		featuresA: { file: `${CTRL}/UsersController.cs`, cwe: "CWE-639", category: "authz" },
		featuresB: { file: `${CTRL}/UsersController.cs`, cwe: "CWE-862", category: "authz" },
		note: "Same Users missing-authz, split into two CWE labels.",
	},
	{
		a: "f-0008-4", b: "f-0008-18", same: true,
		featuresA: { file: `${CTRL}/VersionsController.cs`, cwe: "CWE-306", category: "auth" },
		featuresB: { file: `${CTRL}/VersionsController.cs`, cwe: "CWE-862", category: "auth" },
		note: "Same Versions [AllowAnonymous] keystone, reworded.",
	},
	{
		a: "f-0008-38", b: "f-0008-40", same: true,
		featuresA: { file: "backend/UvA.Workflow.Api/appsettings.json", cwe: "CWE-798", category: "auth" },
		featuresB: { file: "backend/UvA.Workflow.Api/appsettings.json", cwe: "CWE-798", category: "auth" },
		note: "Same committed-key finding twice.",
	},
	{
		a: "f-0008-9", b: "f-0008-30", same: true,
		featuresA: { file: `${CTRL}/InvitesController.cs`, cwe: "CWE-862", category: "authz" },
		featuresB: { file: `${CTRL}/InvitesController.cs`, cwe: "CWE-862", category: "authz" },
		note: "Same InvitesController missing-authz.",
	},
	{
		a: "f-0008-ssrf", b: "f-0008-xss", same: false,
		featuresA: { file: `${SVC}/EffectService.cs`, cwe: "CWE-918", category: "ssrf" },
		featuresB: { file: "frontend/src/components/MarkdownRenderer.tsx", cwe: "CWE-79", category: "xss" },
		note: "SSRF vs stored-XSS — distinct vulns, must not merge.",
	},
	{
		a: "f-0008-keys", b: "f-0008-versions", same: false,
		featuresA: { file: "backend/UvA.Workflow.Api/appsettings.json", cwe: "CWE-798", category: "auth" },
		featuresB: { file: `${CTRL}/VersionsController.cs`, cwe: "CWE-306", category: "auth" },
		note: "Committed keys vs anon Versions upload — distinct roots.",
	},
	{
		a: "f-0008-invite", b: "f-0008-users", same: false,
		featuresA: { file: `${CTRL}/InvitesController.cs`, cwe: "CWE-862", category: "authz" },
		featuresB: { file: `${CTRL}/UsersController.cs`, cwe: "CWE-639", category: "authz" },
		note: "Two different controllers' authz gaps — distinct.",
	},
];
