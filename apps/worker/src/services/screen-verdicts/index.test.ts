// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Screen fail-open routing tests (spec T14).
 *
 * Locks in the prioritizer (not gate) contract: only a confident majority
 * `refute` rejects; `uncertain` flows on as `screen_uncertain`; `support` stays
 * `queued`; a live `exploited` PoC is never demoted; the legacy
 * `{category}_screen_rejected.json` is honored only when the panel did not run;
 * and missing/malformed files are skipped without throwing.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { NormalizedVuln } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { applyScreenVerdicts } from "./index.js";

const dirs: string[] = [];
afterEach(() => {
	for (const d of dirs.splice(0)) {
		fs.rmSync(d, { recursive: true, force: true });
	}
});

function tmpDeliverables(): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "screen-verdicts-"));
	dirs.push(dir);
	return dir;
}

function write(dir: string, name: string, data: unknown): void {
	fs.writeFileSync(
		path.join(dir, name),
		typeof data === "string" ? data : JSON.stringify(data),
	);
}

function vuln(
	category: NormalizedVuln["category"],
	id: string,
	disposition: NormalizedVuln["disposition"] = "queued",
	evidenceText = "",
): NormalizedVuln {
	return { category, id, raw: { ID: id }, disposition, evidenceText };
}

function makeLogger(): { logger: ActivityLogger; warns: string[] } {
	const warns: string[] = [];
	const logger: ActivityLogger = {
		info() {},
		warn(message) {
			warns.push(message);
		},
		error() {},
	};
	return { logger, warns };
}

describe("applyScreenVerdicts — panel fail-open routing", () => {
	it("refute → unverified_screen_rejected, carrying a refuting voter's reason", () => {
		const dir = tmpDeliverables();
		write(dir, "injection_screen_verdicts.json", [
			{
				id: "INJ-VULN-01",
				decision: "refute",
				votes: [
					{ voter: 1, lens: "exploitability", verdict: "support", reason: "looks real" },
					{ voter: 2, lens: "data-flow", verdict: "refute", reason: "input is parameterized" },
				],
			},
		]);
		const vulns = [vuln("injection", "INJ-VULN-01")];
		applyScreenVerdicts(vulns, dir, makeLogger().logger);
		expect(vulns[0]?.disposition).toBe("unverified_screen_rejected");
		expect(vulns[0]?.evidenceText).toBe("input is parameterized");
	});

	it("uncertain → screen_uncertain (non-terminal; flows to exploitation)", () => {
		const dir = tmpDeliverables();
		write(dir, "xss_screen_verdicts.json", [
			{ id: "XSS-VULN-01", decision: "uncertain", votes: [] },
		]);
		const vulns = [vuln("xss", "XSS-VULN-01")];
		applyScreenVerdicts(vulns, dir, makeLogger().logger);
		expect(vulns[0]?.disposition).toBe("screen_uncertain");
	});

	it("support → stays queued (flows to exploitation)", () => {
		const dir = tmpDeliverables();
		write(dir, "ssrf_screen_verdicts.json", [
			{ id: "SSRF-VULN-01", decision: "support", votes: [] },
		]);
		const vulns = [vuln("ssrf", "SSRF-VULN-01")];
		applyScreenVerdicts(vulns, dir, makeLogger().logger);
		expect(vulns[0]?.disposition).toBe("queued");
	});

	it("never demotes an exploited finding, even on refute", () => {
		const dir = tmpDeliverables();
		write(dir, "auth_screen_verdicts.json", [
			{
				id: "AUTH-VULN-01",
				decision: "refute",
				votes: [{ voter: 1, lens: "auth-model", verdict: "refute", reason: "token verified" }],
			},
		]);
		const vulns = [vuln("auth", "AUTH-VULN-01", "exploited", "live PoC")];
		applyScreenVerdicts(vulns, dir, makeLogger().logger);
		expect(vulns[0]?.disposition).toBe("exploited");
		expect(vulns[0]?.evidenceText).toBe("live PoC");
	});

	it("never demotes an exploited finding on an uncertain verdict", () => {
		const dir = tmpDeliverables();
		write(dir, "injection_screen_verdicts.json", [
			{ id: "INJ-VULN-02", decision: "uncertain", votes: [] },
		]);
		const vulns = [vuln("injection", "INJ-VULN-02", "exploited")];
		applyScreenVerdicts(vulns, dir, makeLogger().logger);
		expect(vulns[0]?.disposition).toBe("exploited");
	});

	it("synthesizes an appendix entry for a refuted id dropped from the queue", () => {
		const dir = tmpDeliverables();
		write(dir, "authz_screen_verdicts.json", [
			{
				id: "AUTHZ-VULN-09",
				decision: "refute",
				votes: [{ voter: 1, lens: "scope", verdict: "refute", reason: "same-tenant only" }],
			},
		]);
		const vulns: NormalizedVuln[] = [];
		applyScreenVerdicts(vulns, dir, makeLogger().logger);
		expect(vulns).toHaveLength(1);
		expect(vulns[0]).toMatchObject({
			category: "authz",
			id: "AUTHZ-VULN-09",
			disposition: "unverified_screen_rejected",
			evidenceText: "same-tenant only",
		});
	});

	it("does not synthesize entries for non-refute decisions on missing ids", () => {
		const dir = tmpDeliverables();
		write(dir, "ssrf_screen_verdicts.json", [
			{ id: "SSRF-VULN-77", decision: "uncertain", votes: [] },
			{ id: "SSRF-VULN-88", decision: "support", votes: [] },
		]);
		const vulns: NormalizedVuln[] = [];
		applyScreenVerdicts(vulns, dir, makeLogger().logger);
		expect(vulns).toHaveLength(0);
	});
});

describe("applyScreenVerdicts — backward-compatible legacy fallback", () => {
	it("applies legacy _screen_rejected.json when no panel verdicts exist", () => {
		const dir = tmpDeliverables();
		write(dir, "auth_screen_rejected.json", [
			{ id: "AUTH-VULN-01", screen_reason: "JWT is verified server-side" },
		]);
		const vulns = [vuln("auth", "AUTH-VULN-01")];
		applyScreenVerdicts(vulns, dir, makeLogger().logger);
		expect(vulns[0]?.disposition).toBe("unverified_screen_rejected");
		expect(vulns[0]?.evidenceText).toBe("JWT is verified server-side");
	});

	it("panel verdicts win: the legacy file is ignored when verdicts are present", () => {
		const dir = tmpDeliverables();
		write(dir, "auth_screen_verdicts.json", [
			{ id: "AUTH-VULN-01", decision: "support", votes: [] },
		]);
		write(dir, "auth_screen_rejected.json", [
			{ id: "AUTH-VULN-01", screen_reason: "stale legacy refutation" },
		]);
		const vulns = [vuln("auth", "AUTH-VULN-01")];
		applyScreenVerdicts(vulns, dir, makeLogger().logger);
		// `support` keeps it queued; the stale legacy refutation is NOT applied.
		expect(vulns[0]?.disposition).toBe("queued");
	});

	it("legacy fallback also never demotes an exploited finding", () => {
		const dir = tmpDeliverables();
		write(dir, "auth_screen_rejected.json", [
			{ id: "AUTH-VULN-01", screen_reason: "x" },
		]);
		const vulns = [vuln("auth", "AUTH-VULN-01", "exploited")];
		applyScreenVerdicts(vulns, dir, makeLogger().logger);
		expect(vulns[0]?.disposition).toBe("exploited");
	});
});

describe("applyScreenVerdicts — best-effort robustness", () => {
	it("skips a malformed verdicts file without throwing (finding stays queued)", () => {
		const dir = tmpDeliverables();
		write(dir, "xss_screen_verdicts.json", "{ not valid json");
		const vulns = [vuln("xss", "XSS-VULN-01")];
		const { logger, warns } = makeLogger();
		expect(() => applyScreenVerdicts(vulns, dir, logger)).not.toThrow();
		expect(vulns[0]?.disposition).toBe("queued");
		expect(warns.length).toBeGreaterThan(0);
	});

	it("a malformed verdicts file falls back to a present legacy file", () => {
		const dir = tmpDeliverables();
		write(dir, "auth_screen_verdicts.json", "}{ broken");
		write(dir, "auth_screen_rejected.json", [
			{ id: "AUTH-VULN-01", screen_reason: "legacy still applies" },
		]);
		const vulns = [vuln("auth", "AUTH-VULN-01")];
		applyScreenVerdicts(vulns, dir, makeLogger().logger);
		expect(vulns[0]?.disposition).toBe("unverified_screen_rejected");
		expect(vulns[0]?.evidenceText).toBe("legacy still applies");
	});

	it("no screen files at all → dispositions untouched", () => {
		const dir = tmpDeliverables();
		const vulns = [vuln("injection", "INJ-VULN-01")];
		applyScreenVerdicts(vulns, dir, makeLogger().logger);
		expect(vulns[0]?.disposition).toBe("queued");
	});

	it("returns the same array reference for call-site chaining", () => {
		const dir = tmpDeliverables();
		const vulns: NormalizedVuln[] = [];
		expect(applyScreenVerdicts(vulns, dir, makeLogger().logger)).toBe(vulns);
	});
});
