// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { DistributedConfig } from "../../types/config.js";
import { renderIdentities } from "./artifacts.js";
import {
	assembleScanPromptContext,
	SCAN_IDENTITIES_FILE,
	THREAT_MODEL_FILE,
} from "./assemble.js";

let dir: string;

beforeEach(async () => {
	dir = await mkdtemp(join(tmpdir(), "tm-assemble-"));
});

afterEach(async () => {
	await rm(dir, { recursive: true, force: true });
});

describe("assembleScanPromptContext", () => {
	it("returns no fields (every var -> sentinel) when no artifacts/env present", async () => {
		const ctx = await assembleScanPromptContext(dir, null, {});
		expect(ctx).toEqual({});
		expect(ctx.threatModel).toBeUndefined();
		expect(ctx.historicalSeed).toBeUndefined();
		expect(ctx.identities).toBeUndefined();
		expect(ctx.fpRules).toBeUndefined();
	});

	it("populates threatModel from threat_model.json", async () => {
		await writeFile(
			join(dir, THREAT_MODEL_FILE),
			JSON.stringify({
				threats: [
					{
						id: "T1",
						threat: "RCE via insecure deserialization",
						impact: "critical",
						likelihood: "likely",
					},
				],
			}),
		);
		const ctx = await assembleScanPromptContext(dir, null, {});
		expect(ctx.threatModel).toBeDefined();
		expect(ctx.threatModel).toContain("T1");
		expect(ctx.threatModel).toContain("RCE via insecure deserialization");
	});

	it("leaves threatModel unset when threat_model.json is malformed", async () => {
		await writeFile(join(dir, THREAT_MODEL_FILE), "{ not valid json ");
		const ctx = await assembleScanPromptContext(dir, null, {});
		expect(ctx.threatModel).toBeUndefined();
	});

	it("reads fpRules from the SHOR_FP_RULES env var", async () => {
		const ctx = await assembleScanPromptContext(dir, null, {
			SHOR_FP_RULES: "do not re-report self-XSS",
		});
		expect(ctx.fpRules).toBe("do not re-report self-XSS");
	});

	it("renders identities as labels/roles and NEVER surfaces credentials", async () => {
		await writeFile(
			join(dir, SCAN_IDENTITIES_FILE),
			JSON.stringify({
				identities: [
					{
						label: "tenant-admin",
						role: "owner",
						password: "hunter2",
						token: "sk-secret-123",
						cookie: "sess=abc",
						totp_secret: "JBSWY3DPEHPK3PXP",
					},
				],
			}),
		);
		const ctx = await assembleScanPromptContext(dir, null, {});
		expect(ctx.identities).toBeDefined();
		expect(ctx.identities).toContain("tenant-admin");
		expect(ctx.identities).toContain("owner");
		for (const secret of [
			"hunter2",
			"sk-secret-123",
			"sess=abc",
			"JBSWY3DPEHPK3PXP",
		]) {
			expect(ctx.identities).not.toContain(secret);
		}
	});

	it("never surfaces credentials carried on the config argument", async () => {
		const config: DistributedConfig = {
			avoid: [],
			focus: [],
			description: "",
			authentication: {
				login_type: "form",
				login_url: "https://target.example/login",
				credentials: { username: "u", password: "topsecret-pw" },
				success_condition: { type: "url_contains", value: "/dashboard" },
			},
		};
		await writeFile(
			join(dir, SCAN_IDENTITIES_FILE),
			JSON.stringify({ identities: [{ label: "u", role: "user" }] }),
		);
		const ctx = await assembleScanPromptContext(dir, config, {});
		expect(JSON.stringify(ctx)).not.toContain("topsecret-pw");
	});
});

describe("renderIdentities", () => {
	it("is allowlist-driven — emits label/role, never other fields", () => {
		const out = renderIdentities([{ label: "a", role: "admin", secret: "s3cr3t" }]);
		expect(out).toContain("a");
		expect(out).toContain("admin");
		expect(out).not.toContain("s3cr3t");
	});

	it("returns null for empty input", () => {
		expect(renderIdentities([])).toBeNull();
		expect(renderIdentities({})).toBeNull();
	});
});
