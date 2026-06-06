// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ActivityLogger } from "../../types/activity-logger.js";
import {
	checkpointEnabled,
	loadCompletedPhases,
	restoreCheckpoint,
	saveCheckpoint,
} from "./index.js";

const log: ActivityLogger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };

let tmp: string;
let ckptRoot: string;
let deliverables: string;
const SCAN = "11111111-2222-3333-4444-555555555555";

beforeEach(() => {
	tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ckpt-test-"));
	ckptRoot = path.join(tmp, "ckpt");
	deliverables = path.join(tmp, "repo", ".storron", "deliverables");
	fs.mkdirSync(deliverables, { recursive: true });
	process.env.SHOR_CHECKPOINT_DIR = ckptRoot;
});

afterEach(() => {
	process.env.SHOR_CHECKPOINT_DIR = undefined;
	delete process.env.SHOR_CHECKPOINT_DIR;
	fs.rmSync(tmp, { recursive: true, force: true });
});

describe("checkpoint save/restore", () => {
	it("snapshots deliverables and records the phase", () => {
		fs.writeFileSync(path.join(deliverables, "recon_deliverable.md"), "# recon");
		fs.writeFileSync(
			path.join(deliverables, "injection_exploitation_queue.json"),
			'{"vulnerabilities":[{"ID":"INJ-1"}]}',
		);
		saveCheckpoint(SCAN, "prereq", deliverables, log);
		saveCheckpoint(SCAN, "vuln", deliverables, log);
		expect([...loadCompletedPhases(SCAN)].sort()).toEqual(["prereq", "vuln"]);
	});

	it("snapshots ALL deliverables incl. nested subdirs (not just the first file)", () => {
		// Regression: fs.cpSync chmod-EPERM'd on gcsfuse after ONE file, so only
		// scan_identities.json reached the snapshot. The content-only copy must
		// round-trip every file AND nested dirs (e.g. schemas/).
		fs.writeFileSync(path.join(deliverables, "scan_identities.json"), "{}");
		fs.writeFileSync(path.join(deliverables, "pre_recon_deliverable.md"), "# pre");
		fs.writeFileSync(path.join(deliverables, "threat_model.json"), '{"threats":[]}');
		fs.mkdirSync(path.join(deliverables, "schemas"), { recursive: true });
		fs.writeFileSync(
			path.join(deliverables, "schemas", "live_openapi.json"),
			'{"openapi":"3.0"}',
		);

		saveCheckpoint(SCAN, "prereq", deliverables, log);

		const fresh = path.join(tmp, "repo3", ".storron", "deliverables");
		restoreCheckpoint(SCAN, fresh, log);
		for (const rel of [
			"scan_identities.json",
			"pre_recon_deliverable.md",
			"threat_model.json",
			"schemas/live_openapi.json",
		]) {
			expect(fs.existsSync(path.join(fresh, rel)), rel).toBe(true);
		}
		expect(
			fs.readFileSync(path.join(fresh, "schemas/live_openapi.json"), "utf8"),
		).toBe('{"openapi":"3.0"}');
	});

	it("restores deliverables into a fresh dir and returns completed phases", () => {
		fs.writeFileSync(path.join(deliverables, "recon_deliverable.md"), "# recon");
		saveCheckpoint(SCAN, "prereq", deliverables, log);

		// Simulate a fresh execution: a new, empty deliverables dir.
		const fresh = path.join(tmp, "repo2", ".storron", "deliverables");
		const done = restoreCheckpoint(SCAN, fresh, log);

		expect([...done]).toEqual(["prereq"]);
		expect(fs.readFileSync(path.join(fresh, "recon_deliverable.md"), "utf8")).toBe(
			"# recon",
		);
	});

	it("returns empty (no resume) when no checkpoint exists for the scan", () => {
		const done = restoreCheckpoint("no-such-scan", deliverables, log);
		expect(done.size).toBe(0);
	});

	it("is a no-op and disabled when SHOR_CHECKPOINT_DIR is unset", () => {
		delete process.env.SHOR_CHECKPOINT_DIR;
		expect(checkpointEnabled()).toBe(false);
		saveCheckpoint(SCAN, "prereq", deliverables, log); // must not throw
		expect(loadCompletedPhases(SCAN).size).toBe(0);
		expect(restoreCheckpoint(SCAN, deliverables, log).size).toBe(0);
	});

	it("ignores unknown phases in a malformed manifest", () => {
		const scanDir = path.join(ckptRoot, "scans", SCAN);
		fs.mkdirSync(scanDir, { recursive: true });
		fs.writeFileSync(
			path.join(scanDir, "phases.json"),
			'["prereq","bogus","vuln"]',
		);
		expect([...loadCompletedPhases(SCAN)].sort()).toEqual(["prereq", "vuln"]);
	});
});
