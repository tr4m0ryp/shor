// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * End-to-end prompt-build checks: the assembler feeds `loadPrompt`, a real
 * consumer prompt surfaces the threat model, and no `{{...}}` placeholder ever
 * survives the render (the task's hard verification gate).
 */

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PROMPTS_DIR } from "../../paths.js";
import { loadPrompt } from "../prompt-manager.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { assembleScanPromptContext, THREAT_MODEL_FILE } from "./assemble.js";

const LEFTOVER = /\{\{[^}]+\}\}/;
const VARS = { webUrl: "https://target.example", repoPath: "/tmp/repo" };

// Every placeholder the prompt build is responsible for resolving. (Category
// prompts also embed literal SSTI probe payloads like `{{7*7}}` in their bodies,
// which are NOT placeholders and legitimately survive — so consumer prompts are
// checked against this closed set rather than a blanket `{{...}}` regex.)
const CONTEXT_PLACEHOLDERS = [
	"{{THREAT_MODEL}}",
	"{{HISTORICAL_SEED}}",
	"{{PARTITION}}",
	"{{LENS}}",
	"{{VOTER_INDEX}}",
	"{{IDENTITIES}}",
	"{{FP_RULES}}",
	"{{WEB_URL}}",
	"{{REPO_PATH}}",
	"{{LOGIN_INSTRUCTIONS}}",
	"{{RULES_AVOID}}",
	"{{RULES_FOCUS}}",
	"{{AUTH_CONTEXT}}",
	"{{DESCRIPTION}}",
	"{{PLAYWRIGHT_SESSION}}",
];

function expectAllPlaceholdersResolved(rendered: string): void {
	for (const placeholder of CONTEXT_PLACEHOLDERS) {
		expect(rendered).not.toContain(placeholder);
	}
}

const noopLogger: ActivityLogger = {
	info: () => {},
	warn: () => {},
	error: () => {},
};

let dir: string;

beforeEach(async () => {
	dir = await mkdtemp(join(tmpdir(), "tm-integration-"));
});

afterEach(async () => {
	await rm(dir, { recursive: true, force: true });
});

describe("threat-model prompt integration", () => {
	it("renders the producer prompt with no leftover placeholders", async () => {
		const rendered = await loadPrompt(
			"threat-model",
			VARS,
			null,
			noopLogger,
			PROMPTS_DIR,
		);
		expect(rendered).not.toMatch(LEFTOVER);
		expect(rendered).toContain("threat_model.json");
	});

	it("renders a vuln consumer prompt with the (none) sentinel when no model exists", async () => {
		const rendered = await loadPrompt(
			"vuln-injection",
			VARS,
			null,
			noopLogger,
			PROMPTS_DIR,
			{},
		);
		expectAllPlaceholdersResolved(rendered);
		// the _threat-model.txt include is present and resolved to the sentinel.
		expect(rendered).toContain("Engagement threat model");
		expect(rendered).toContain("(none)");
	});

	it("injects the assembled threat-model summary into a vuln consumer prompt", async () => {
		await writeFile(
			join(dir, THREAT_MODEL_FILE),
			JSON.stringify({
				assets: [
					{
						asset: "tenant billing records",
						description: "per-tenant invoices",
						sensitivity: "critical",
					},
				],
				threats: [
					{
						id: "T1",
						threat: "cross-tenant IDOR exposes other tenants' invoices",
						actor: "remote_auth",
						surface: "GET /api/invoices/{id}",
						asset: "tenant billing records",
						impact: "critical",
						likelihood: "likely",
					},
				],
			}),
		);
		const context = await assembleScanPromptContext(dir, null, {});
		const rendered = await loadPrompt(
			"vuln-injection",
			VARS,
			null,
			noopLogger,
			PROMPTS_DIR,
			context,
		);
		expectAllPlaceholdersResolved(rendered);
		expect(rendered).toContain("cross-tenant IDOR");
		expect(rendered).toContain("tenant billing records");
	});
});
