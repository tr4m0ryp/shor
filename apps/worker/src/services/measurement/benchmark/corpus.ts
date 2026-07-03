// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * The fixed labeled benchmark (spec T15). Ground-truth vulns + known-FP labels
 * seeded from the two MANUALLY validated scans (0007/0008 against
 * tr4m0ryp/workflow-pentest) plus a public CVE, so recall/FP/dedup/calibration are
 * measured against a stable yardstick every release.
 *
 * PROVENANCE GAP (stop-condition, flagged): the scan-0007/0008 validations exist
 * only as prose analyst notes, NOT machine-readable labels in-repo. The vulns
 * below are a faithful hand-encoding of that prose (file paths + CWEs from the
 * notes); the calibration/dedup labeled sets live in {@link ./seed-sets}. Treat
 * this as the SEED corpus — extend it as scans are exported to a labels file.
 */

import type { FindingRecord } from "../../../job/findings/types.js";
import type {
	Benchmark,
	BenchmarkFinding,
	FalsePositiveLabel,
	GroundTruthVuln,
} from "./types.js";

const API = "backend/UvA.Workflow.Api";

/** Genuinely-valid vulns from scan-0007 (validated ~7-8 real of 57 raw). */
const SCAN_0007_VULNS: readonly GroundTruthVuln[] = [
	{
		id: "gt-0007-versions-anon",
		source: "scan-0007",
		cwe: "CWE-306",
		category: "auth",
		severity: "critical",
		locations: [{ file: `${API}/Controllers/VersionsController.cs`, symbol: "AllowAnonymous" }],
		aliases: ["VersionsController", "AllowAnonymous", "ModelServiceResolver"],
		description:
			"[AllowAnonymous] POST /Versions/{version}: unauthenticated workflow-model injection into a process-global singleton; root enabler for privesc/SSRF/stored-XSS.",
	},
	{
		id: "gt-0007-artifact-anon-token",
		source: "scan-0007",
		cwe: "CWE-287",
		category: "auth",
		severity: "high",
		locations: [{ file: `${API}/Controllers/AnswersController.cs`, symbol: "AllowAnonymous" }],
		aliases: ["AnswersController", "artifact", "HMAC"],
		description:
			"Anonymous artifact download gated only by an HMAC JWT whose signing key is committed; ValidateIssuer/Audience=false, not user-bound, replayable.",
	},
	{
		id: "gt-0007-invites-no-authz",
		source: "scan-0007",
		cwe: "CWE-862",
		category: "authz",
		severity: "high",
		locations: [{ file: `${API}/Controllers/InvitesController.cs`, symbol: "SendInvite" }],
		aliases: ["InvitesController", "SendInvite"],
		description: "InvitesController.SendInvite has zero authz; any user drives EduId invites + enumeration.",
	},
	{
		id: "gt-0007-users-idor",
		source: "scan-0007",
		cwe: "CWE-639",
		category: "authz",
		severity: "high",
		locations: [{ file: `${API}/Controllers/UsersController.cs`, symbol: "Get" }],
		aliases: ["UsersController", "IDOR"],
		description: "GET /Users/{id} has no rights check — insecure direct object reference.",
	},
	{
		id: "gt-0007-rubric-stored-xss",
		source: "scan-0007",
		cwe: "CWE-79",
		category: "xss",
		severity: "high",
		locations: [{ file: "frontend/src/components/MarkdownRenderer.tsx", symbol: "rehypeRaw" }],
		aliases: ["MarkdownRenderer", "rehypeRaw", "RubricEntry"],
		description: "MarkdownRenderer.tsx uses rehypeRaw (no sanitizer) on model-injectable RubricEntry.Description; no CSP.",
	},
	{
		id: "gt-0007-effectservice-ssrf",
		source: "scan-0007",
		cwe: "CWE-918",
		category: "ssrf",
		severity: "high",
		locations: [{ file: `${API}/Services/EffectService.cs`, line: 233, symbol: "ServiceCall" }],
		aliases: ["EffectService", "ServiceCall", "BaseUrl"],
		description: "EffectService.ServiceCall builds an HttpClient to a model-defined BaseUrl/Url with no egress/metadata-IP allowlist (reachable via the Versions injection).",
	},
	{
		id: "gt-0007-toctou-lost-update",
		source: "scan-0007",
		cwe: "CWE-362",
		category: "logic",
		severity: "medium",
		locations: [{ file: `${API}/Services/EffectService.cs`, symbol: "ReplaceOneAsync" }],
		aliases: ["ReplaceOneAsync", "TOCTOU", "concurrency"],
		description: "Check-then-act on submission/account-create with no unique indexes and no Mongo transactions — lost-update / double-submit races.",
	},
	{
		id: "gt-0007-user-enumeration",
		source: "scan-0007",
		cwe: "CWE-204",
		category: "auth",
		severity: "low",
		locations: [{ file: `${API}/Controllers/UsersController.cs`, symbol: "Find" }],
		aliases: ["find", "VerifyEmail", "enumeration"],
		description: "GET /Users/find + VerifyEmail expose directory enumeration via response differences.",
	},
];

/** Distinct criticals surfaced/confirmed by scan-0008 (committed keys + chain). */
const SCAN_0008_VULNS: readonly GroundTruthVuln[] = [
	{
		id: "gt-0008-committed-keys",
		source: "scan-0008",
		cwe: "CWE-798",
		category: "auth",
		severity: "critical",
		locations: [{ file: `${API}/appsettings.json`, symbol: "SigningKey" }],
		aliases: ["appsettings", "CanvasLti", "ImpersonationKey", "SigningKey", "admin"],
		description: "Hardcoded credentials committed in appsettings.json (CanvasLti HMAC, S3 artifact SigningKey, ImpersonationKey, Mongo admin/admin) — git-verified, live in config.",
	},
	{
		id: "gt-0008-markdig-email-xss",
		source: "scan-0008",
		cwe: "CWE-79",
		category: "xss",
		severity: "high",
		locations: [{ file: `${API}/Services/EffectService.cs`, symbol: "Markdig" }],
		aliases: ["Markdig", "email", "raw-html"],
		description: "Backend Markdig raw-HTML email rendering yields stored XSS from model-injectable content.",
	},
];

/** A public advisory, showing the package/version shortlist path. */
const PUBLIC_CVE_VULNS: readonly GroundTruthVuln[] = [
	{
		id: "gt-cve-2021-44228-log4shell",
		source: "cve",
		cveId: "CVE-2021-44228",
		cwe: "CWE-502",
		category: "injection",
		severity: "critical",
		pkg: "org.apache.logging.log4j:log4j-core",
		affectedVersion: "<2.15.0",
		locations: [{ file: "pom.xml", symbol: "log4j-core" }],
		aliases: ["log4j", "log4shell", "jndi"],
		description: "Log4Shell — JNDI lookup in log4j-core enables remote code execution (dependency-CVE shortlist example).",
	},
];

/** Known false positives — reproducing one on a later run is a regression. */
const FALSE_POSITIVES: readonly FalsePositiveLabel[] = [
	{
		id: "fp-0008-path-traversal-trio",
		source: "scan-0008",
		cwe: "CWE-22",
		category: "injection",
		locations: [
			{ file: `${API}/Providers/FileSystemProvider.cs` },
			{ file: `${API}/Providers/DictionaryProvider.cs` },
		],
		reason: "Asserts a DictionaryProvider -> FileSystemProvider path-traversal flow that does not exist: uploads use an in-memory dict; the FS provider only runs at startup over a trusted dir.",
	},
	{
		id: "fp-0007-mock-oidc-8090",
		source: "scan-0007",
		cwe: "CWE-346",
		category: "auth",
		locations: [{ file: "mock-oidc/server.py", symbol: "8090" }],
		reason: "Findings against the Flask/Werkzeug mock OIDC on :8090 (CORS *, alg:none, JWKS disclosure, open redirect) — the test IdP, no source in the target repo; out of scope.",
	},
];

/** The seed benchmark: all ground-truth vulns + known-FP labels. */
export const SEED_BENCHMARK: Benchmark = {
	vulns: [...SCAN_0007_VULNS, ...SCAN_0008_VULNS, ...PUBLIC_CVE_VULNS],
	falsePositives: FALSE_POSITIVES,
};

/** Return the fixed seed benchmark (a stable, frozen reference). */
export function loadBenchmark(): Benchmark {
	return SEED_BENCHMARK;
}

/** Categorical confidence -> numeric P(TP) prior, when no number is emitted. */
const CONFIDENCE_PRIOR: Record<string, number> = {
	confirmed: 0.9,
	firm: 0.6,
	tentative: 0.35,
	unverified: 0.1,
};

/** Map a categorical confidence to its numeric prior (0.5 when unknown). */
export function confidenceToProb(label: string | undefined): number {
	if (!label) return 0.5;
	const p = CONFIDENCE_PRIOR[label];
	return typeof p === "number" ? p : 0.5;
}

/**
 * Adapt a live {@link FindingRecord} into the grader's injected shape. Keeps the
 * grader pure/testable while letting the real pipeline feed it. `symbol`/`pkg` are
 * left undefined — the positional (file+line) tier carries the match.
 */
export function fromFindingRecord(f: FindingRecord): BenchmarkFinding {
	const loc = f.vulnerable_code_location ?? { file: "", line: 0 };
	const out: BenchmarkFinding = {
		id: String(f.id),
		category: f.category,
		cwe: f.cwe,
		file: loc.file ?? "",
		confidenceLabel: f.confidence,
	};
	if (typeof loc.line === "number" && loc.line > 0)
		return { ...out, line: loc.line, ...clusterOf(f) };
	return { ...out, ...clusterOf(f) };
}

function clusterOf(f: FindingRecord): { clusterId?: string } {
	return typeof f.cluster_id === "string" && f.cluster_id.trim()
		? { clusterId: f.cluster_id.trim() }
		: {};
}
