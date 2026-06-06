// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * `applyOracleDispositions` override semantics, plus an end-to-end pass through
 * `collectFindings` proving the executable-oracle verdict OVERRIDES the markdown
 * parse and lands on the §6.1 record as `oracle_disposition`.
 */

import { promises as fsp } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { collectFindings } from "../../job/findings/index.js";
import type { NormalizedVuln, OracleDisposition } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { applyOracleDispositions } from "./index.js";

const logger = { info() {}, warn() {}, error() {} } as ActivityLogger;

const tmpDirs: string[] = [];
async function mkDeliverables(): Promise<string> {
	const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "shor-oracle-apply-"));
	tmpDirs.push(dir);
	return dir;
}
afterEach(async () => {
	for (const d of tmpDirs.splice(0)) await fsp.rm(d, { recursive: true, force: true });
});

function vuln(id: string, disposition: NormalizedVuln["disposition"]): NormalizedVuln {
	return { category: "injection", id, raw: { ID: id }, disposition, evidenceText: "" };
}

async function writeDispositionsFile(dir: string, map: Record<string, OracleDisposition>): Promise<void> {
	await fsp.writeFile(path.join(dir, "oracle_dispositions.json"), JSON.stringify(map));
}

describe("applyOracleDispositions (unit)", () => {
	it("DEMOTES a markdown-exploited finding the oracle could not reproduce", async () => {
		const dir = await mkDeliverables();
		await writeDispositionsFile(dir, { "INJ-VULN-01": "blocked" });
		const vulns = [vuln("INJ-VULN-01", "exploited")];

		applyOracleDispositions(vulns, dir, logger);

		expect(vulns[0]?.disposition).toBe("blocked");
		expect(vulns[0]?.raw.oracle_disposition).toBe("blocked");
	});

	it("PROMOTES a markdown-blocked finding the oracle replayed successfully", async () => {
		const dir = await mkDeliverables();
		await writeDispositionsFile(dir, { "INJ-VULN-01": "exploited" });
		const vulns = [vuln("INJ-VULN-01", "blocked")];

		applyOracleDispositions(vulns, dir, logger);

		expect(vulns[0]?.disposition).toBe("exploited");
		expect(vulns[0]?.raw.oracle_disposition).toBe("exploited");
	});

	it("not_replayable keeps the markdown disposition as the fallback", async () => {
		const dir = await mkDeliverables();
		await writeDispositionsFile(dir, { "INJ-VULN-01": "not_replayable" });
		const vulns = [vuln("INJ-VULN-01", "exploited")];

		applyOracleDispositions(vulns, dir, logger);

		expect(vulns[0]?.disposition).toBe("exploited"); // unchanged
		expect(vulns[0]?.raw.oracle_disposition).toBe("not_replayable");
	});

	it("is identity when no oracle_dispositions.json exists", async () => {
		const dir = await mkDeliverables();
		const vulns = [vuln("INJ-VULN-01", "exploited")];
		applyOracleDispositions(vulns, dir, logger);
		expect(vulns[0]?.disposition).toBe("exploited");
		expect(vulns[0]?.raw.oracle_disposition).toBeUndefined();
	});
});

async function writeQueue(dir: string, id: string): Promise<void> {
	const queue = {
		vulnerabilities: [{ ID: id, vulnerability_type: "SQLi", location: "src/db.ts:10", missing_defense: "no params" }],
	};
	await fsp.writeFile(path.join(dir, "injection_exploitation_queue.json"), JSON.stringify(queue));
}

async function writeEvidence(dir: string, id: string, section: string): Promise<void> {
	const md = [`## ${section}`, "", `### ${id}: SQL Injection`, "Tampered the id parameter.", ""].join("\n");
	await fsp.writeFile(path.join(dir, "injection_exploitation_evidence.md"), md);
}

describe("collectFindings end-to-end (oracle overrides markdown → record.oracle_disposition)", () => {
	it("oracle DEMOTES a prose-exploited finding and stamps the record", async () => {
		const dir = await mkDeliverables();
		const id = "INJ-VULN-01";
		await writeQueue(dir, id);
		await writeEvidence(dir, id, "Successfully Exploited Vulnerabilities"); // markdown says exploited
		await writeDispositionsFile(dir, { [id]: "blocked" }); // oracle says blocked

		const rec = (await collectFindings(dir, logger)).find((f) => f.id === id);

		expect(rec).toBeDefined();
		expect(rec?.disposition).toBe("blocked");
		expect(rec?.oracle_disposition).toBe("blocked");
		expect(rec?.confidence).not.toBe("confirmed"); // demoted out of confirmed
	});

	it("oracle PROMOTES a prose-blocked finding to confirmed-exploited", async () => {
		const dir = await mkDeliverables();
		const id = "INJ-VULN-01";
		await writeQueue(dir, id);
		await writeEvidence(dir, id, "Potential Vulnerabilities (Validation Blocked)"); // markdown says blocked
		await writeDispositionsFile(dir, { [id]: "exploited" }); // oracle says exploited

		const rec = (await collectFindings(dir, logger)).find((f) => f.id === id);

		expect(rec?.disposition).toBe("exploited");
		expect(rec?.oracle_disposition).toBe("exploited");
		expect(rec?.confidence).toBe("confirmed");
	});
});
