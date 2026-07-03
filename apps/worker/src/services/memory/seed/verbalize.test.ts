// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import type { SeedExemplar } from "./types.js";
import {
	SEED_DOC_LABELS,
	seedMetadataPrefix,
	verbalizeSeed,
} from "./verbalize.js";

const FULL: SeedExemplar = {
	technique: "SSRF via redirect",
	aliases: ["redirect SSRF"],
	preconditions: "fetcher follows redirects",
	rootCause: "allowlist checked once",
	source: "attacker URL",
	sink: "internal endpoint",
	probeSignal: "internal content returned",
	pocSkeleton: "GET /fetch?url=https://evil/redirect",
	cwe: "CWE-918",
	capecId: "CAPEC-664",
	tags: ["ssrf", "redirect"],
	noveltyTier: "flagship",
	provenance: { source: "Test", url: "https://example.com" },
};

describe("verbalizeSeed", () => {
	it("renders all labels in order with the metadata prefix and PoC as code text", () => {
		const v = verbalizeSeed(FULL);
		// Every label present, in the fixed order.
		let cursor = -1;
		for (const label of SEED_DOC_LABELS) {
			const at = v.doc.indexOf(`${label}:`);
			expect(at).toBeGreaterThan(cursor);
			cursor = at;
		}
		expect(v.text.startsWith(v.metadataPrefix)).toBe(true);
		expect(v.metadataPrefix).toContain("CWE=CWE-918");
		expect(v.metadataPrefix).toContain("CAPEC=CAPEC-664");
		expect(v.metadataPrefix).toContain("tier=flagship");
		expect(v.doc).toContain("DATA FLOW: attacker URL -> internal endpoint");
		expect(v.doc).toContain("TECHNIQUE: SSRF via redirect (aka redirect SSRF)");
		expect(v.doc).toContain("CWE+CAPEC: CWE-918 / CAPEC-664");
		expect(v.codeText).toBe("GET /fetch?url=https://evil/redirect");
	});

	it("renders n/a for absent optionals and empty code text with no skeleton", () => {
		const bare: SeedExemplar = {
			technique: "Bare",
			preconditions: "",
			rootCause: "",
			source: "",
			sink: "",
			probeSignal: "",
			pocSkeleton: "",
			tags: [],
			noveltyTier: "novel",
			provenance: { source: "Test" },
		};
		const v = verbalizeSeed(bare);
		expect(v.codeText).toBe("");
		expect(v.doc).toContain("PRECONDITIONS: n/a");
		expect(v.doc).toContain("CWE+CAPEC: n/a / n/a");
		expect(seedMetadataPrefix(bare)).toContain("tags=n/a");
	});
});
