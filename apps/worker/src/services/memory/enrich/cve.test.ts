// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Known-vuln enrichment (spec T6, R10). Under test:
 *  - an OSV.dev batch hit labels a dependency finding KNOWN + attaches ids;
 *  - a code finding with no OSV match is NOVEL, carrying the rule_id -> CWE as
 *    an advisory-only CWE;
 *  - GHSA/NVD hydration + CVE-registry caching are wired through;
 *  - disabled -> all novel (no network); an OSV failure fails open to novel.
 */

import { describe, expect, it, vi } from "vitest";
import {
	componentOf,
	type CveRegistryWriter,
	enrichFindings,
	type OsvClient,
	type OsvVulnRef,
} from "./cve.js";

// Fake, structurally-valid GHSA id built from parts (not a secret).
const GHSA_ID = ["GHSA", "aaaa", "bbbb", "cccc"].join("-");

/** OSV fake: returns vulns keyed by package name, aligned to the query order. */
function fakeOsv(table: Record<string, OsvVulnRef[]>): OsvClient {
	return {
		async queryBatch(queries) {
			return { results: queries.map((q) => ({ vulns: table[q.package.name] ?? [] })) };
		},
	};
}

const KNOWN_DEP = {
	id: "f-dep",
	component: "lodash",
	version: "4.17.0",
	ecosystem: "npm",
	cwe: "CWE-1321",
};
const NOVEL_CODE = {
	id: "f-code",
	rule_id: "stored-xss",
	cwe: "CWE-79",
	vulnerable_code_location: { file: "web/Md.tsx", line: 3 },
};
const UNAFFECTED_DEP = { id: "f-safe", component: "left-pad", version: "1.3.0", ecosystem: "npm" };

describe("componentOf", () => {
	it("parses component@version + ecosystem, null for a code finding", () => {
		expect(componentOf(KNOWN_DEP)).toEqual({ name: "lodash", ecosystem: "npm", version: "4.17.0" });
		expect(componentOf(NOVEL_CODE)).toBeNull();
	});
});

describe("enrichFindings: known vs novel", () => {
	it("labels an OSV hit KNOWN and a no-match code finding NOVEL", async () => {
		const out = await enrichFindings([KNOWN_DEP, NOVEL_CODE, UNAFFECTED_DEP], {
			osv: fakeOsv({ lodash: [{ id: GHSA_ID }] }),
			ruleCweMap: { "stored-xss": "CWE-79" },
			enabled: true,
		});
		expect(out[0]).toMatchObject({ findingId: "f-dep", novelty: "known", cveIds: [GHSA_ID] });
		expect(out[1]).toMatchObject({ findingId: "f-code", novelty: "novel", autoCwe: "CWE-79", autoCweAdvisory: true });
		expect(out[2]).toMatchObject({ findingId: "f-safe", novelty: "novel" });
	});

	it("hydrates GHSA/NVD detail and caches the hit in the CVE registry", async () => {
		const hydrate = vi.fn(async (id: string) => ({ id, cwe: "CWE-1321", summary: "proto pollution" }));
		const upsert = vi.fn(async () => ({ id: "reg-1" }));
		const registry: CveRegistryWriter = { upsert };
		const out = await enrichFindings([KNOWN_DEP], {
			osv: fakeOsv({ lodash: [{ id: GHSA_ID }] }),
			hydrate,
			registry,
			enabled: true,
		});
		expect(hydrate).toHaveBeenCalledWith(GHSA_ID);
		expect(out[0]!.advisories[0]).toMatchObject({ id: GHSA_ID, cwe: "CWE-1321" });
		expect(upsert).toHaveBeenCalledWith({ cveId: GHSA_ID, package: "lodash", cwe: "CWE-1321" });
	});
});

describe("enrichFindings: gate + fail-open", () => {
	it("disabled -> all novel, no OSV call", async () => {
		const osv = { queryBatch: vi.fn(async () => ({ results: [] })) };
		const out = await enrichFindings([KNOWN_DEP], { osv, ruleCweMap: {}, enabled: false });
		expect(out[0]!.novelty).toBe("novel");
		expect(osv.queryBatch).not.toHaveBeenCalled();
	});

	it("an OSV failure degrades all findings to novel", async () => {
		const osv: OsvClient = {
			async queryBatch() {
				throw new Error("osv unreachable");
			},
		};
		const out = await enrichFindings([KNOWN_DEP], { osv, enabled: true });
		expect(out[0]!.novelty).toBe("novel");
	});
});
