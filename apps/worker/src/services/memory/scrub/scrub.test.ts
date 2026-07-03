// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Scrub-stage guarantees under test (all with injected seams — no gitleaks/
 * trufflehog/Presidio binaries required):
 *  - a planted secret is quarantined and appears NOWHERE in the result;
 *  - PII (emails, UUIDs, internal hosts) is redacted by the builtin layer;
 *  - a broken engine fails CLOSED (no clean output);
 *  - nothing secret reaches the injected logger.
 */

import { describe, expect, it } from "vitest";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import { createBuiltinPiiAnalyzer, scrub } from "./index.js";
import { resolveSecretHits } from "./secrets.js";
import type { PiiAnalyzer, ScrubDeps, SecretDetector } from "./types.js";

// A fake, never-live token (structured like a GitHub PAT) planted for tests.
// Built from parts so no secret-shaped literal sits in source (would trip secret scanners); value is fake and never-live.
const FAKE_SECRET = ["ghp", "TESTONLYFAKE0123456789abcdefTESTONLY"].join("_");

function collectingLogger(sink: string[]): ActivityLogger {
	const record = (message: string, attrs?: Record<string, unknown>) =>
		sink.push(`${message} ${JSON.stringify(attrs ?? {})}`);
	return { info: record, warn: record, error: record };
}

function valueDetector(value: string): SecretDetector {
	return async (text) =>
		text.includes(value) ? [{ source: "injected", ruleId: "fake-pat", value }] : [];
}

function deps(overrides: Partial<ScrubDeps> = {}): ScrubDeps {
	return {
		secretDetectors: [valueDetector(FAKE_SECRET)],
		piiAnalyzers: [createBuiltinPiiAnalyzer()],
		piiEngine: "injected",
		...overrides,
	};
}

describe("scrub: secret quarantine", () => {
	it("quarantines a planted secret — absent from clean and from the whole result", async () => {
		const input = `token=${FAKE_SECRET} used twice: ${FAKE_SECRET}`;
		const result = await scrub(input, deps());
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.clean).not.toContain(FAKE_SECRET);
		expect(result.clean).toMatch(/\[QUARANTINED-SECRET:[0-9a-f]{16}\]/);
		expect(result.quarantined).toHaveLength(1);
		expect(result.quarantined[0]?.occurrences).toBe(2);
		expect(result.quarantined[0]?.preview).toBe(`ghp_****(len=${FAKE_SECRET.length})`);
		// The raw value must not appear ANYWHERE in the returned structure.
		expect(JSON.stringify(result)).not.toContain(FAKE_SECRET);
	});

	it("excises span-located hits (gitleaks --redact style) without ever seeing the value", async () => {
		const fakeAws = "AKIA" + "FAKEFAKEFAKEFAKE";
		const input = `before ${fakeAws} after`;
		const start = input.indexOf("AKIA");
		const spanDetector: SecretDetector = async () => [
			{ source: "gitleaks", ruleId: "aws-access-key", span: { start, end: start + 20 } },
		];
		const result = await scrub(input, deps({ secretDetectors: [spanDetector] }));
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.clean).not.toContain(fakeAws);
		expect(result.clean).toContain("before ");
		expect(result.clean).toContain(" after");
		expect(result.quarantined[0]?.ruleId).toBe("aws-access-key");
	});

	it("scrubs nested finding objects, leaving structure and clean fields intact", async () => {
		const finding = {
			title: "Hardcoded token",
			severity: "high",
			line: 42,
			evidence: { snippet: `Authorization: Bearer ${FAKE_SECRET}`, notes: ["contact admin@corp.example.com"] },
		};
		const result = await scrub(finding, deps());
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		const clean = result.clean as typeof finding;
		expect(JSON.stringify(result)).not.toContain(FAKE_SECRET);
		expect(clean.evidence.snippet).toContain("[QUARANTINED-SECRET:");
		expect(clean.evidence.notes[0]).toContain("[REDACTED-EMAIL_ADDRESS]");
		expect(clean.title).toBe("Hardcoded token");
		expect(clean.line).toBe(42);
		// Input is never mutated.
		expect(finding.evidence.snippet).toContain(FAKE_SECRET);
	});
});

describe("scrub: PII redaction (builtin layer)", () => {
	it("redacts emails, tenant UUIDs, internal hostnames, and URL authorities", async () => {
		const input = [
			"reported by jane.doe@tenant-a.com",
			"tenant 5dd78584-1234-4abc-9def-0123456789ab",
			"callback https://user:pw" + "@db.tenant.internal:5432/path",
			"host api.corp",
		].join("\n");
		const result = await scrub(input, deps({ secretDetectors: [] }));
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.clean).not.toContain("jane.doe@tenant-a.com");
		expect(result.clean).not.toContain("5dd78584-1234-4abc-9def-0123456789ab");
		expect(result.clean).not.toContain("db.tenant.internal");
		expect(result.clean).toContain("[REDACTED-EMAIL_ADDRESS]");
		expect(result.clean).toContain("[REDACTED-TENANT_ID]");
		const types = result.pii.map((p) => p.entityType);
		expect(types).toContain("EMAIL_ADDRESS");
		expect(types).toContain("TENANT_ID");
	});

	it("redacts injected NER entities (Presidio-style person names)", async () => {
		const input = "Contact John Smith for access.";
		const ner: PiiAnalyzer = async (text) => {
			const start = text.indexOf("John Smith");
			return [{ entityType: "PERSON", start, end: start + "John Smith".length, score: 0.9 }];
		};
		const result = await scrub(input, deps({ secretDetectors: [], piiAnalyzers: [ner] }));
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.clean).toBe("Contact [REDACTED-PERSON] for access.");
	});
});

describe("scrub: fail-closed", () => {
	it("fails closed when a secret detector cannot run", async () => {
		const broken: SecretDetector = async () => {
			throw new Error("gitleaks not on PATH");
		};
		const result = await scrub(`text with ${FAKE_SECRET}`, deps({ secretDetectors: [broken] }));
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.clean).toBeNull();
		expect(result.reason).toContain("gitleaks not on PATH");
		expect(JSON.stringify(result)).not.toContain(FAKE_SECRET);
	});

	it("fails closed when a PII analyzer cannot run", async () => {
		const broken: PiiAnalyzer = async () => {
			throw new Error("presidio sidecar unreachable");
		};
		const result = await scrub("any text", deps({ piiAnalyzers: [broken] }));
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.clean).toBeNull();
	});

	it("fails closed on an unlocatable hit instead of passing the secret through", async () => {
		const unlocatable: SecretDetector = async () => [{ source: "injected", ruleId: "mystery" }];
		const result = await scrub("some text", deps({ secretDetectors: [unlocatable] }));
		expect(result.ok).toBe(false);
	});
});

describe("scrub: log hygiene", () => {
	it("never emits secret material or scanned text through the logger", async () => {
		const lines: string[] = [];
		const okResult = await scrub(`k=${FAKE_SECRET}`, deps({ logger: collectingLogger(lines) }));
		const failResult = await scrub(
			`k=${FAKE_SECRET}`,
			deps({
				logger: collectingLogger(lines),
				secretDetectors: [
					async () => {
						throw new Error("engine down");
					},
				],
			}),
		);
		expect(okResult.ok).toBe(true);
		expect(failResult.ok).toBe(false);
		expect(lines.length).toBeGreaterThan(0);
		for (const line of lines) expect(line).not.toContain(FAKE_SECRET);
	});
});

describe("resolveSecretHits (pure core)", () => {
	it("dedups by fingerprint across detectors and counts occurrences", () => {
		const text = `a ${FAKE_SECRET} b ${FAKE_SECRET}`;
		const { edits, quarantined, rawValues } = resolveSecretHits(text, [
			{ source: "injected", ruleId: "fake-pat", value: FAKE_SECRET },
			{ source: "trufflehog", ruleId: "GitHub", value: FAKE_SECRET },
		]);
		expect(quarantined).toHaveLength(1);
		expect(quarantined[0]?.occurrences).toBe(4); // 2 occurrences x 2 detectors
		expect(edits).toHaveLength(4);
		expect(rawValues).toEqual([FAKE_SECRET]);
		expect(JSON.stringify(quarantined)).not.toContain(FAKE_SECRET);
	});

	it("handles empty input and no-hit text", async () => {
		const result = await scrub("", deps());
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.clean).toBe("");
		expect(result.quarantined).toHaveLength(0);
	});
});
