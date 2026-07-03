// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * A tiny STIX 2.1 fixture standing in for the multi-MB MITRE CAPEC bundle (which
 * is NEVER committed — the CLI reads it from `SHOR_CAPEC_STIX_PATH`). Two
 * `attack-pattern` objects plus noise (an identity object, a revoked pattern) so
 * the parser's selection + skip logic is exercised. `unknown`-typed on purpose:
 * `parseCapecStix` must cope with untrusted, loosely-shaped input.
 */

export const SAMPLE_CAPEC_BUNDLE: unknown = {
	type: "bundle",
	id: "bundle--0000",
	objects: [
		{
			type: "identity",
			id: "identity--capec",
			name: "The MITRE Corporation",
		},
		{
			type: "attack-pattern",
			id: "attack-pattern--sqli",
			name: "SQL Injection",
			description:
				"An adversary crafts input strings so that when they are parsed as SQL they alter the intended query.",
			x_capec_abstraction: "Standard",
			x_capec_status: "Stable",
			x_capec_prerequisites: [
				"The application builds SQL from untrusted input.",
				"No parameterization or escaping is applied.",
			],
			x_capec_domains: ["Software"],
			x_capec_example_instances: [
				"POST /login with username set to ' OR '1'='1 returns an authenticated session.",
			],
			x_capec_consequences: {
				Confidentiality: ["Read Data"],
				Integrity: ["Modify Data"],
			},
			aliases: ["SQLi"],
			modified: "2022-09-29T00:00:00.000Z",
			external_references: [
				{
					source_name: "capec",
					external_id: "CAPEC-66",
					url: "https://capec.mitre.org/data/definitions/66.html",
				},
				{ source_name: "cwe", external_id: "CWE-89" },
			],
		},
		{
			type: "attack-pattern",
			id: "attack-pattern--revoked",
			name: "Obsolete Pattern",
			revoked: true,
			external_references: [{ source_name: "capec", external_id: "CAPEC-999" }],
		},
		{
			type: "attack-pattern",
			id: "attack-pattern--pathtraversal",
			name: "Relative Path Traversal",
			description:
				"An adversary uses ../ sequences in a path parameter to escape the intended directory and read arbitrary files.",
			x_capec_abstraction: "Detailed",
			x_capec_prerequisites: ["A file path is derived from user input."],
			x_capec_domains: ["Software"],
			x_capec_example_instances: [],
			x_capec_consequences: { Confidentiality: ["Read Files or Directories"] },
			external_references: [
				{
					source_name: "capec",
					external_id: "CAPEC-139",
					url: "https://capec.mitre.org/data/definitions/139.html",
				},
				{ source_name: "cwe", external_id: "CWE-23" },
			],
		},
	],
};
