// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Calibration regression tests (T13 + T10) for the SYNCHRONOUS `gradeFindings`.
 *
 * Guards the four contract behaviours: thin evidence -> tentative + severity
 * capped (never dropped); oracle-confirmed -> confirmed + reachable; HARNESS_ONLY
 * caps severity; threat_id is set from the best-matching threat; and a
 * missing/malformed threat model fails open (labels unchanged, finding kept).
 */

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { FindingRecord } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { THREAT_MODEL_FILE, type Threat } from "../threat-model/index.js";
import { GRADES_FILE, type GradeRow, gradeFindings } from "./index.js";

const logger = { info() {}, warn() {}, error() {} } as unknown as ActivityLogger;

const tmpDirs: string[] = [];
async function mkDeliverables(): Promise<string> {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), "shor-grader-"));
	tmpDirs.push(dir);
	return dir;
}
afterEach(async () => {
	for (const d of tmpDirs.splice(0)) await fs.rm(d, { recursive: true, force: true });
});

function mkFinding(o: Partial<FindingRecord> = {}): FindingRecord {
	return {
		id: "F1",
		validation_note: "",
		title: "Finding",
		category: "xss",
		cwe: "CWE-79",
		owasp_category: "A03",
		severity: "high",
		confidence: "firm",
		evidence: "",
		safe_poc: "",
		repro_steps: [],
		vulnerable_code_location: { file: "src/app.ts", line: 1 },
		missing_defense: "",
		remediation: "",
		status: "new",
		fingerprint: "fp",
		partialFingerprints: {},
		...o,
	};
}

function threat(o: Partial<Threat> = {}): Threat {
	return {
		id: "T1",
		threat: "",
		actor: "remote_unauth",
		surface: "",
		asset: "",
		impact: "high",
		likelihood: "likely",
		status: "open",
		controls: "",
		evidence: "",
		...o,
	};
}

async function writeThreats(dir: string, threats: Threat[]): Promise<void> {
	await fs.writeFile(
		path.join(dir, THREAT_MODEL_FILE),
		JSON.stringify({
			system_context: "",
			assets: [],
			entry_points: [],
			threats,
			deprioritized: [],
			provenance: { sources: [], notes: "" },
		}),
	);
}

async function writeGrades(dir: string, rows: GradeRow[]): Promise<void> {
	await fs.writeFile(path.join(dir, GRADES_FILE), JSON.stringify({ grades: rows }));
}

describe("gradeFindings calibration", () => {
	it("thin evidence -> tentative and severity capped, never dropped", async () => {
		const dir = await mkDeliverables();
		await writeThreats(dir, [
			threat({
				id: "T1",
				surface: "product search query parameter rendering",
				asset: "catalog page",
				threat: "reflected script injection in search",
				impact: "high",
			}),
		]);
		await writeGrades(dir, [
			{ id: "F1", evidence_score: 0, severity: "high", reachability: "REACHABLE", confidence: "tentative" },
		]);
		const finding = mkFinding({
			category: "xss",
			title: "Reflected XSS in search",
			severity: "high",
			confidence: "firm",
			vulnerable_code_location: { file: "src/search.ts", line: 12 },
		});

		const out = gradeFindings([finding], { deliverablesPath: dir, logger });

		expect(out).toHaveLength(1); // never dropped
		expect(out[0]?.confidence).toBe("tentative");
		expect(out[0]?.severity).toBe("medium"); // capped down from the high baseline
		expect(out[0]?.threat_id).toBe("T1");
	});

	it("oracle-confirmed exploit -> confirmed + REACHABLE", async () => {
		const dir = await mkDeliverables();
		await writeThreats(dir, [
			threat({
				id: "T2",
				surface: "admin users endpoint",
				asset: "tenant records",
				actor: "remote_auth",
				impact: "medium",
				likelihood: "possible",
			}),
		]);
		const finding = mkFinding({
			id: "F1",
			category: "authz",
			title: "IDOR on admin users",
			severity: "medium",
			confidence: "firm",
			oracle_disposition: "exploited",
			evidence: "Accessed another tenant's record by tampering the id.",
			repro_steps: ["GET /admin/users/2"],
			vulnerable_code_location: { file: "src/admin.ts", line: 42 },
		});

		const out = gradeFindings([finding], { deliverablesPath: dir, logger });

		expect(out).toHaveLength(1);
		expect(out[0]?.confidence).toBe("confirmed");
		expect(out[0]?.reachability).toBe("REACHABLE");
		expect(out[0]?.severity).toBe("high"); // raised from medium by confirmation
		expect(out[0]?.threat_id).toBe("T2");
	});

	it("HARNESS_ONLY reachability caps severity (without dropping)", async () => {
		const dir = await mkDeliverables();
		await writeThreats(dir, [
			threat({
				id: "T3",
				surface: "report builder query",
				asset: "database",
				impact: "critical",
			}),
		]);
		await writeGrades(dir, [
			{ id: "F1", evidence_score: 1, severity: "high", reachability: "HARNESS_ONLY", confidence: "firm" },
		]);
		const finding = mkFinding({
			category: "injection",
			title: "SQL injection in report builder",
			severity: "high",
			reachability: "HARNESS_ONLY",
			safe_poc: "' OR 1=1 --",
			evidence: "Query concatenates the report name directly.",
			vulnerable_code_location: { file: "src/report.ts", line: 88 },
		});

		const out = gradeFindings([finding], { deliverablesPath: dir, logger });

		expect(out).toHaveLength(1);
		expect(out[0]?.reachability).toBe("HARNESS_ONLY");
		expect(out[0]?.severity).toBe("medium"); // capped from the critical baseline
	});

	it("threat_id is set from the best-matching threat, not a sibling", async () => {
		const dir = await mkDeliverables();
		await writeThreats(dir, [
			threat({ id: "T_AUTH", surface: "login session token issuance", asset: "user session" }),
			threat({ id: "T_SSRF", surface: "outbound webhook url fetch", asset: "internal metadata" }),
		]);
		const finding = mkFinding({
			category: "ssrf",
			title: "SSRF via webhook url",
			evidence: "The webhook url is fetched server-side.",
			vulnerable_code_location: { file: "src/webhook.ts", line: 10 },
		});

		const out = gradeFindings([finding], { deliverablesPath: dir, logger });

		expect(out[0]?.threat_id).toBe("T_SSRF");
	});

	it("fails open: a malformed threat model leaves labels unchanged and keeps the finding", async () => {
		const dir = await mkDeliverables();
		await fs.writeFile(path.join(dir, THREAT_MODEL_FILE), "{ this is not valid json");
		const finding = mkFinding({ severity: "high", confidence: "firm" });

		const out = gradeFindings([finding], { deliverablesPath: dir, logger });

		expect(out).toHaveLength(1);
		expect(out[0]?.severity).toBe("high");
		expect(out[0]?.confidence).toBe("firm");
		expect(out[0]?.threat_id).toBeUndefined();
		expect(out[0]?.reachability).toBeUndefined();
	});

	it("never drops findings: output preserves every input id", async () => {
		const dir = await mkDeliverables();
		await writeThreats(dir, [threat({ id: "T1", surface: "search", asset: "page" })]);
		const findings = [
			mkFinding({ id: "A", category: "xss", title: "XSS in search" }),
			mkFinding({ id: "B", category: "auth", title: "Weak session token" }),
			mkFinding({ id: "C", category: "ssrf", title: "SSRF in fetch" }),
		];

		const out = gradeFindings(findings, { deliverablesPath: dir, logger });

		expect(out.map((f) => f.id)).toEqual(["A", "B", "C"]);
	});
});
