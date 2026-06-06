// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AgentContext } from "../../job/pipeline.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { Authentication } from "../../types/config.js";
import { renderIdentities, SCAN_IDENTITIES_FILE } from "../threat-model/index.js";
import { bootstrapIdentities } from "./bootstrap.js";
import { collectIdentities } from "./collect.js";
import { buildIdentityManifest, writeIdentityManifest } from "./manifest.js";

/** Credential material that must NEVER reach an artifact (ADR-050). */
const SECRETS = [
	"primary-secret",
	"hunter2",
	"s3cr3t-pw",
	"JBSWY3DPEHPK3PXP",
	"primary-user",
	"memberx",
];

const MULTI: Authentication = {
	login_type: "form",
	login_url: "https://target.example/login",
	credentials: { username: "primary-user", password: "primary-secret" },
	success_condition: { type: "url_contains", value: "/dash" },
	identities: [
		{
			label: "tenant-admin",
			role: "owner",
			credentials: {
				username: "adminx",
				password: "hunter2",
				totp_secret: "JBSWY3DPEHPK3PXP",
			},
		},
		{
			label: "member",
			role: "user",
			credentials: { username: "memberx", password: "s3cr3t-pw" },
		},
	],
};

const SINGLE: Authentication = {
	login_type: "form",
	login_url: "https://target.example/login",
	credentials: { username: "only-user", password: "only-secret" },
	success_condition: { type: "url_contains", value: "/dash" },
};

let dir: string;

beforeEach(async () => {
	dir = await mkdtemp(join(tmpdir(), "identity-"));
});

afterEach(async () => {
	await rm(dir, { recursive: true, force: true });
});

describe("collectIdentities", () => {
	it("resolves primary + secondaries as credential-free metadata", () => {
		const ids = collectIdentities(MULTI);
		expect(ids.map((i) => i.label)).toEqual(["primary", "tenant-admin", "member"]);
		expect(ids[0]?.isPrimary).toBe(true);
		expect(ids[1]?.isPrimary).toBe(false);
		// session labels are namespaced + disjoint from agent1..5 phase sessions
		expect(ids.map((i) => i.sessionLabel)).toEqual([
			"identity-primary",
			"identity-tenant-admin",
			"identity-member",
		]);
		const blob = JSON.stringify(ids);
		for (const secret of SECRETS) expect(blob).not.toContain(secret);
	});

	it("returns [] for an unauthenticated (no-config) scan", () => {
		expect(collectIdentities(null)).toEqual([]);
		expect(collectIdentities(undefined)).toEqual([]);
	});
});

describe("identity manifest producer", () => {
	it("writes scan_identities.json with ONLY label/role — no credential leak", async () => {
		const file = await writeIdentityManifest(
			dir,
			buildIdentityManifest(collectIdentities(MULTI)),
		);
		expect(file).toBe(join(dir, SCAN_IDENTITIES_FILE));

		const raw = await readFile(file, "utf8");
		expect(JSON.parse(raw).identities).toEqual([
			{ label: "primary" },
			{ label: "tenant-admin", role: "owner" },
			{ label: "member", role: "user" },
		]);

		// No credential KEY survives into the manifest...
		for (const key of [
			"credentials",
			"username",
			"password",
			"totp_secret",
			"token",
			"cookie",
		]) {
			expect(raw).not.toContain(key);
		}
		// ...and no credential VALUE either.
		for (const secret of SECRETS) expect(raw).not.toContain(secret);
	});

	it("falls back to a primary-only manifest + single-identity note", async () => {
		const manifest = buildIdentityManifest(collectIdentities(SINGLE));
		expect(manifest.identities).toEqual([{ label: "primary" }]);
		expect(manifest.note).toMatch(/single-identity/i);

		const raw = await readFile(
			await writeIdentityManifest(dir, manifest),
			"utf8",
		);
		expect(raw).not.toContain("only-secret");
		expect(raw).not.toContain("only-user");
	});

	it("round-trips through the assembler reader without surfacing a secret", async () => {
		await writeIdentityManifest(dir, buildIdentityManifest(collectIdentities(MULTI)));
		const parsed = JSON.parse(
			await readFile(join(dir, SCAN_IDENTITIES_FILE), "utf8"),
		);
		const rendered = renderIdentities(parsed);
		expect(rendered).not.toBeNull();
		expect(rendered).toContain("tenant-admin");
		expect(rendered).toContain("owner");
		for (const secret of SECRETS) expect(rendered ?? "").not.toContain(secret);
	});
});

describe("bootstrapIdentities (best-effort orchestration)", () => {
	const MULTI_YAML = `
authentication:
  login_type: form
  login_url: https://target.example/login
  credentials:
    username: primary-user
    password: primary-secret
  success_condition:
    type: url_contains
    value: /dash
  identities:
    - label: tenant-admin
      role: owner
      credentials:
        username: adminx
        password: hunter2
        totp_secret: JBSWY3DPEHPK3PXP
    - label: member
      role: user
      credentials:
        username: memberx
        password: s3cr3t-pw
`;

	function makeCtx(configYaml?: string): AgentContext {
		const noop = (): void => undefined;
		const logger: ActivityLogger = { info: noop, warn: noop, error: noop };
		return {
			params: {
				scanId: "scan-1",
				targetUrl: "https://target.example",
				repoPath: dir,
				...(configYaml !== undefined && { configYaml }),
			},
			deliverablesPath: join(dir, ".storron", "deliverables"),
			container: { config: { deliverablesSubdir: ".storron/deliverables" } },
			logger,
		} as unknown as AgentContext;
	}

	it("writes the manifest + per-identity storage-state slots, leaking no secret", async () => {
		await bootstrapIdentities(makeCtx(MULTI_YAML));

		const manifestPath = join(dir, ".storron", "deliverables", SCAN_IDENTITIES_FILE);
		const raw = await readFile(manifestPath, "utf8");
		expect(JSON.parse(raw).identities.map((i: { label: string }) => i.label)).toEqual([
			"primary",
			"tenant-admin",
			"member",
		]);
		for (const secret of SECRETS) expect(raw).not.toContain(secret);

		// Each identity got an isolated, empty Playwright storage-state slot.
		const slot = join(
			dir,
			".storron",
			".playwright-cli",
			"identities",
			"identity-tenant-admin",
			"storage-state.json",
		);
		expect(JSON.parse(await readFile(slot, "utf8"))).toEqual({
			cookies: [],
			origins: [],
		});
	});

	it("degrades to a single-identity manifest when no config is present", async () => {
		await bootstrapIdentities(makeCtx());
		const raw = await readFile(
			join(dir, ".storron", "deliverables", SCAN_IDENTITIES_FILE),
			"utf8",
		);
		const manifest = JSON.parse(raw);
		expect(manifest.identities).toEqual([]);
		expect(manifest.note).toMatch(/single-identity/i);
	});

	it("never throws, even on a malformed config", async () => {
		await expect(
			bootstrapIdentities(makeCtx("authentication: { not: valid")),
		).resolves.toBeUndefined();
	});
});
