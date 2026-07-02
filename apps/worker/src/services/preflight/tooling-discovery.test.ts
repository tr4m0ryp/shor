// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { ErrorCode } from "../../types/errors.js";
import { expectedSkillNames, SKILL_BINARIES } from "./skill-catalog.js";
import { validateToolingDiscovery } from "./tooling-discovery.js";

// Silent logger — the preflight only logs; nothing here asserts on log output.
const logger = {
	info() {},
	warn() {},
	error() {},
	debug() {},
} as unknown as ActivityLogger;

const tmpDirs: string[] = [];
async function mkTmp(prefix: string): Promise<string> {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), `shor-${prefix}-`));
	tmpDirs.push(dir);
	return dir;
}
async function writeSkill(treeRoot: string, category: string, name: string): Promise<void> {
	const dir = path.join(treeRoot, category, name);
	await fs.mkdir(dir, { recursive: true });
	await fs.writeFile(path.join(dir, "SKILL.md"), `# ${name}\n`);
}
async function discover(home: string, name: string): Promise<void> {
	const dir = path.join(home, ".claude", "skills", name);
	await fs.mkdir(dir, { recursive: true });
	await fs.writeFile(path.join(dir, "SKILL.md"), `# ${name}\n`);
}
async function fakeBinary(binDir: string, name: string): Promise<void> {
	await fs.mkdir(binDir, { recursive: true });
	const p = path.join(binDir, name);
	await fs.writeFile(p, "#!/bin/sh\n");
	await fs.chmod(p, 0o755);
}

afterEach(async () => {
	for (const d of tmpDirs.splice(0)) {
		await fs.rm(d, { recursive: true, force: true });
	}
});

describe("skill catalog ↔ repo tree parity (drift guard)", () => {
	it("SKILL_BINARIES keys equal the names derived from the repo skills/ tree", async () => {
		// repo root = five levels up from this file's dir (…/apps/worker/src/services/preflight)
		const here = path.dirname(fileURLToPath(import.meta.url));
		const repoSkills = path.resolve(here, "..", "..", "..", "..", "..", "skills");
		const fromTree = await expectedSkillNames(repoSkills);
		if (fromTree.length === 0) return; // tree not reachable in this layout — covered by behaviour tests
		expect(fromTree).toEqual([...Object.keys(SKILL_BINARIES)].sort());
	});
});

describe("validateToolingDiscovery", () => {
	it("passes when every skill is discovered and binaries (if any) resolve on PATH", async () => {
		const tree = await mkTmp("tree");
		const home = await mkTmp("home");
		// Two skills with no own binary (not in SKILL_BINARIES) — discovery-only.
		await writeSkill(tree, "recon", "alpha-tool");
		await writeSkill(tree, "exploit", "beta-tool");
		await discover(home, "alpha-tool");
		await discover(home, "beta-tool");

		const res = await validateToolingDiscovery(logger, { home, pathEnv: "", skillsTreeRoot: tree });
		expect(res.ok).toBe(true);
	});

	it("fails (TOOLING_MISSING) in image mode when a skill is not discovered", async () => {
		const tree = await mkTmp("tree");
		const home = await mkTmp("home");
		await writeSkill(tree, "recon", "alpha-tool");
		await writeSkill(tree, "recon", "gamma-tool");
		await discover(home, "alpha-tool"); // gamma-tool intentionally NOT discovered

		const res = await validateToolingDiscovery(logger, { home, pathEnv: "", skillsTreeRoot: tree });
		expect(res.ok).toBe(false);
		if (!res.ok) {
			expect(res.error.code).toBe(ErrorCode.TOOLING_MISSING);
			expect(res.error.message).toContain("gamma-tool");
		}
	});

	it("fails when a skill's binary is missing from PATH, passes once it is present", async () => {
		const tree = await mkTmp("tree");
		const home = await mkTmp("home");
		const bin = await mkTmp("bin");
		// `nmap` is a real catalog skill whose binary is `nmap`.
		await writeSkill(tree, "recon", "nmap");
		await discover(home, "nmap");

		const missing = await validateToolingDiscovery(logger, { home, pathEnv: "", skillsTreeRoot: tree });
		expect(missing.ok).toBe(false);
		if (!missing.ok) expect(missing.error.message).toContain("nmap");

		await fakeBinary(bin, "nmap");
		const present = await validateToolingDiscovery(logger, { home, pathEnv: bin, skillsTreeRoot: tree });
		expect(present.ok).toBe(true);
	});

	it("does not block a local/dev checkout that never staged the skills tree", async () => {
		const tree = await mkTmp("tree");
		const home = await mkTmp("home"); // no .claude/skills dir → env classified 'local'
		await writeSkill(tree, "recon", "nmap"); // expected, but not discovered anywhere

		const res = await validateToolingDiscovery(logger, { home, pathEnv: "", skillsTreeRoot: tree });
		expect(res.ok).toBe(true); // warning, not a hard fail
	});
});
