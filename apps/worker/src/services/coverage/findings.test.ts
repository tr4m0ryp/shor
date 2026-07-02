// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Findings-convergence reader tests (task 007).
 *
 * `makeQueueFindingsReader` reads each vuln agent's on-disk exploitation queue
 * to surface the CURRENT findings count. Reads are confined to the deliverables
 * dir and best-effort: a vuln agent's missing/garbled file degrades to 0, a
 * non-vuln agent (no queue) yields `undefined` ("no convergence signal").
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getQueueFilename } from "../../ai/queue-schemas.js";
import type { AgentName } from "../../types/agents.js";
import { makeQueueFindingsReader } from "./findings.js";

describe("makeQueueFindingsReader", () => {
	let dir: string;

	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), "shor-findings-"));
	});
	afterEach(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	/** Write a raw queue body under the vuln agent's queue filename. */
	function writeQueue(agent: AgentName, body: string): void {
		const filename = getQueueFilename(agent);
		if (!filename) throw new Error(`${agent} is not a vuln agent`);
		fs.writeFileSync(path.join(dir, filename), body, "utf8");
	}

	it("counts the vulnerabilities array for a vuln agent", () => {
		writeQueue(
			"injection-vuln",
			JSON.stringify({ vulnerabilities: [{ ID: "A" }, { ID: "B" }, { ID: "C" }] }),
		);
		expect(makeQueueFindingsReader(dir)("injection-vuln")).toBe(3);
	});

	it("returns 0 for an empty queue (clean negative is a valid outcome)", () => {
		writeQueue("xss-vuln", JSON.stringify({ vulnerabilities: [] }));
		expect(makeQueueFindingsReader(dir)("xss-vuln")).toBe(0);
	});

	it("returns 0 when the queue file is missing", () => {
		expect(makeQueueFindingsReader(dir)("auth-vuln")).toBe(0);
	});

	it("returns 0 for a malformed/garbled queue file (never throws)", () => {
		writeQueue("ssrf-vuln", "{ not valid json");
		expect(makeQueueFindingsReader(dir)("ssrf-vuln")).toBe(0);
	});

	it("returns 0 when vulnerabilities is absent or not an array", () => {
		writeQueue("authz-vuln", JSON.stringify({ notes: "no array here" }));
		expect(makeQueueFindingsReader(dir)("authz-vuln")).toBe(0);
	});

	it("returns undefined (no signal) for non-vuln agents", () => {
		const read = makeQueueFindingsReader(dir);
		expect(read("recon")).toBeUndefined();
		expect(read("report")).toBeUndefined();
		// Exploit agents consume the queue but do not own one → no findings signal.
		expect(read("injection-exploit")).toBeUndefined();
	});
});
