// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Cross-tenant pool write-path guarantees under test (task 014, spec T2):
 *  - flag OFF -> no write (the default posture);
 *  - flag ON but audit not passed -> no write;
 *  - flag ON + audit but NO consent -> no write + a logged consent decision;
 *  - all four gates hold -> a `global_pool` row with `source_tenant` + k-anon;
 *  - a PLANTED SECRET is absent from the pooled payload AND from the embed
 *    inputs (vectors are embeddings of scrubbed text — invertible, R4);
 *  - a scrub failure fails CLOSED — nothing embedded or pooled.
 */

import { describe, expect, it } from "vitest";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import { createEmbedClient, type EmbedClient } from "../embed/index.js";
import {
	createBuiltinPiiAnalyzer,
	type ScrubDeps,
	type SecretDetector,
} from "../scrub/index.js";
import {
	type ConsentRecord,
	type ConsentStore,
	type GlobalPoolWriter,
	type PoolingContext,
	promoteFindingToPool,
	promoteFindingsToPool,
} from "./index.js";

// Fake, never-live PAT-shaped token, built from parts so no secret-shaped
// literal sits in source (would trip the pre-push secret scanner); value is fake.
const FAKE_SECRET = ["ghp", "TESTONLYFAKE0123456789abcdefTESTONLY"].join("_");

const CTX: PoolingContext = { tenantId: "t1", projectId: "p1", scanId: "s1" };

function valueDetector(value: string): SecretDetector {
	return async (text) =>
		text.includes(value) ? [{ source: "injected", ruleId: "fake", value }] : [];
}

function scrubDeps(overrides: Partial<ScrubDeps> = {}): ScrubDeps {
	return {
		secretDetectors: [valueDetector(FAKE_SECRET)],
		piiAnalyzers: [createBuiltinPiiAnalyzer()],
		piiEngine: "injected",
		...overrides,
	};
}

interface FakeEmbed {
	client: EmbedClient;
	textInputs: string[];
	codeInputs: string[];
}

function fakeEmbed(): FakeEmbed {
	const textInputs: string[] = [];
	const codeInputs: string[] = [];
	const client: EmbedClient = {
		enabled: true,
		async embedText(texts) {
			textInputs.push(...texts);
			return { model: "text", dim: 2, embeddings: texts.map(() => [0.1, 0.2]), tokenCounts: texts.map(() => 3) };
		},
		async embedCode(texts) {
			codeInputs.push(...texts);
			return { model: "code", dim: 2, embeddings: texts.map(() => [0.3, 0.4]), tokenCounts: texts.map(() => 3) };
		},
		async rerank() {
			return [];
		},
	};
	return { client, textInputs, codeInputs };
}

function fakePool(): { writer: GlobalPoolWriter; calls: Record<string, unknown>[] } {
	const calls: Record<string, unknown>[] = [];
	return {
		calls,
		writer: {
			async insert(input) {
				calls.push(input as Record<string, unknown>);
				return { id: `pool-${calls.length}` };
			},
		},
	};
}

function consentStore(record: ConsentRecord | null): ConsentStore {
	return { async lookup() { return record; } };
}

const GRANTED: ConsentRecord = { tenantId: "t1", granted: true, basis: "DPA-2026-0001" };

interface CapturedLog {
	logger: ActivityLogger;
	entries: { level: string; message: string; attrs?: Record<string, unknown> }[];
}

function capturingLogger(): CapturedLog {
	const entries: CapturedLog["entries"] = [];
	const push = (level: string) => (message: string, attrs?: Record<string, unknown>) =>
		entries.push({ level, message, ...(attrs ? { attrs } : {}) });
	return { entries, logger: { info: push("info"), warn: push("warn"), error: push("error") } };
}

const FINDING = {
	title: "Stored XSS",
	cwe: "CWE-79",
	severity: "high",
	confidence: "confirmed",
	method: "get",
	route: "/x",
	source: "req.query.q",
	sink: "res.send",
	code_snippet: `const token = "${FAKE_SECRET}"; res.send(req.query.q);`,
	evidence: `leaked ${FAKE_SECRET} in the response body`,
	vulnerable_code_location: { file: "a.js", line: 1 },
	fingerprint: "fp-abc",
	cluster_id: "cl_abc",
};

describe("promoteFindingToPool: all gates hold", () => {
	it("pools the canonical finding with source_tenant + k-anon and NO planted secret", async () => {
		const embed = fakeEmbed();
		const pool = fakePool();
		const out = await promoteFindingToPool(FINDING, { ...CTX, novelty: "novel" }, {
			embed: embed.client,
			scrubDeps: scrubDeps(),
			consent: consentStore(GRANTED),
			pool: pool.writer,
			enabled: true,
			auditPassed: true,
		});

		expect(out.written).toBe(true);
		if (!out.written) return;
		expect(out.poolId).toBe("pool-1");
		expect(out.kAnonCount).toBe(1);
		expect(out.quarantinedSecrets).toBe(1);

		// Vectors are embeddings of SCRUBBED text — the secret never reached embed.
		for (const input of [...embed.textInputs, ...embed.codeInputs]) {
			expect(input).not.toContain(FAKE_SECRET);
			expect(input).toContain("[QUARANTINED-SECRET");
		}

		// One pool row, tagged with provenance + k-anon + both vectors.
		expect(pool.calls).toHaveLength(1);
		const row = pool.calls[0] as Record<string, unknown>;
		expect(row).toMatchObject({ kind: "finding", sourceTenant: "t1", kAnonCount: 1, vecText: [0.1, 0.2], vecCode: [0.3, 0.4] });
		const payload = row.payload as Record<string, unknown>;
		expect(payload).toMatchObject({ cwe: "CWE-79", severity: "high", clusterId: "cl_abc", novelty: "novel" });

		// The planted secret is absent from the ENTIRE pooled payload.
		expect(JSON.stringify(pool.calls)).not.toContain(FAKE_SECRET);
	});

	it("honors a k-anon seed override (clamped to >= 1, integer)", async () => {
		const embed = fakeEmbed();
		const pool = fakePool();
		const out = await promoteFindingToPool(FINDING, { ...CTX, kAnonCount: 4 }, {
			embed: embed.client,
			scrubDeps: scrubDeps(),
			consent: consentStore(GRANTED),
			pool: pool.writer,
			enabled: true,
			auditPassed: true,
		});
		expect(out.written && out.kAnonCount).toBe(4);
		expect((pool.calls[0] as Record<string, unknown>).kAnonCount).toBe(4);
	});
});

describe("promoteFindingToPool: fail-closed gates", () => {
	const base = () => ({
		embed: fakeEmbed(),
		pool: fakePool(),
	});

	it("no-ops when the master flag is OFF (default)", async () => {
		const { embed, pool } = base();
		const out = await promoteFindingToPool(FINDING, CTX, {
			embed: embed.client, scrubDeps: scrubDeps(), consent: consentStore(GRANTED), pool: pool.writer,
			enabled: false, auditPassed: true,
		});
		expect(out).toEqual({ written: false, reason: "flag_off" });
		expect(pool.calls).toHaveLength(0);
		expect(embed.textInputs).toHaveLength(0);
	});

	it("no-ops when the red-team audit flag is not set", async () => {
		const { embed, pool } = base();
		const out = await promoteFindingToPool(FINDING, CTX, {
			embed: embed.client, scrubDeps: scrubDeps(), consent: consentStore(GRANTED), pool: pool.writer,
			enabled: true, auditPassed: false,
		});
		expect(out).toEqual({ written: false, reason: "audit_not_passed" });
		expect(pool.calls).toHaveLength(0);
	});

	it("no-ops + LOGS the decision when there is no consent record", async () => {
		const { embed, pool } = base();
		const cap = capturingLogger();
		const out = await promoteFindingToPool(FINDING, CTX, {
			embed: embed.client, scrubDeps: scrubDeps(), consent: consentStore(null), pool: pool.writer,
			logger: cap.logger, enabled: true, auditPassed: true,
		});
		expect(out).toEqual({ written: false, reason: "no_consent" });
		expect(pool.calls).toHaveLength(0);
		expect(embed.textInputs).toHaveLength(0);
		const consentLog = cap.entries.find((e) => e.message === "pooling: consent check");
		expect(consentLog?.attrs).toMatchObject({ tenant: "t1", granted: false });
	});

	it("no-ops when no embed server is configured", async () => {
		delete process.env.SHOR_EMBED_URL;
		const pool = fakePool();
		const out = await promoteFindingToPool(FINDING, CTX, {
			embed: createEmbedClient(), scrubDeps: scrubDeps(), consent: consentStore(GRANTED), pool: pool.writer,
			enabled: true, auditPassed: true,
		});
		expect(out).toEqual({ written: false, reason: "embed_disabled" });
		expect(pool.calls).toHaveLength(0);
	});

	it("fails CLOSED on a scrub error — nothing embedded or pooled", async () => {
		const { embed, pool } = base();
		const throwing: SecretDetector = async () => {
			throw new Error("engine unavailable");
		};
		const out = await promoteFindingToPool(FINDING, CTX, {
			embed: embed.client, scrubDeps: scrubDeps({ secretDetectors: [throwing] }), consent: consentStore(GRANTED), pool: pool.writer,
			enabled: true, auditPassed: true,
		});
		expect(out).toEqual({ written: false, reason: "scrub_failed" });
		expect(embed.textInputs).toHaveLength(0);
		expect(pool.calls).toHaveLength(0);
	});
});

describe("promoteFindingsToPool: batch", () => {
	it("pools each canonical independently, in order", async () => {
		const embed = fakeEmbed();
		const pool = fakePool();
		const outs = await promoteFindingsToPool([FINDING, { ...FINDING, cluster_id: "cl_2" }], CTX, {
			embed: embed.client, scrubDeps: scrubDeps(), consent: consentStore(GRANTED), pool: pool.writer,
			enabled: true, auditPassed: true,
		});
		expect(outs.map((o) => o.written)).toEqual([true, true]);
		expect(pool.calls).toHaveLength(2);
	});
});
