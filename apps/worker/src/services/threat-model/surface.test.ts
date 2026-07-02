// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { renderTargetSurface } from "./surface.js";

describe("renderTargetSurface", () => {
	let dir: string;
	beforeEach(() => {
		dir = mkdtempSync(join(tmpdir(), "surface-"));
	});
	afterEach(() => {
		rmSync(dir, { recursive: true, force: true });
	});

	it("returns undefined when no recon artifact exists yet", async () => {
		expect(await renderTargetSurface(dir, "http://10.0.0.1")).toBeUndefined();
	});

	it("extracts distinct same-host origins (separate ports) from the recon deliverable", async () => {
		writeFileSync(
			join(dir, "recon_deliverable.md"),
			[
				"SPA on http://35.204.213.18 (nginx).",
				"REST API at http://35.204.213.18:8080/swagger/index.html (Kestrel).",
				"OIDC: GET http://35.204.213.18:8090/auth issues a code.",
				"Repeat ref to http://35.204.213.18:8080/Users/1 should dedupe.",
			].join("\n"),
		);
		const out = await renderTargetSurface(dir, "http://35.204.213.18");
		expect(out).toBe(
			"- http://35.204.213.18\n- http://35.204.213.18:8080\n- http://35.204.213.18:8090",
		);
	});

	it("scopes to the target host — off-host origins (schema/doc URLs) are dropped", async () => {
		writeFileSync(
			join(dir, "recon_deliverable.md"),
			"API http://35.204.213.18:8080 documented per https://json-schema.org/draft and https://swagger.io.",
		);
		const out = await renderTargetSurface(dir, "http://35.204.213.18");
		expect(out).toContain("http://35.204.213.18:8080");
		expect(out).not.toContain("json-schema.org");
		expect(out).not.toContain("swagger.io");
	});

	it("merges origins from the coverage manifest too, sorted by port", async () => {
		writeFileSync(
			join(dir, "coverage_manifest.json"),
			JSON.stringify({
				observedLiveOnly: [
					"POST http://35.204.213.18:8090/token — issues JWTs",
					"GET http://35.204.213.18:8080/swagger/v1/swagger.json",
				],
			}),
		);
		const out = await renderTargetSurface(dir, "http://35.204.213.18");
		// Primary origin (from webUrl) first, then :8080, then :8090.
		expect(out).toBe(
			"- http://35.204.213.18\n- http://35.204.213.18:8080\n- http://35.204.213.18:8090",
		);
	});
});
