// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Runtime tooling-discovery preflight.
 *
 * Turns the two SILENT failure modes that make a scan useless — (a) the Claude
 * Agent SDK discovers no skills, (b) an offensive tool's binary is missing from
 * PATH — into a LOUD, actionable startup error, asserted in the exact same
 * environment the agents run in.
 *
 * Two checks:
 *   1. Skill discovery. The SDK runs with `settingSources:["user"]` and
 *      `HOME=/tmp` (Dockerfile.base `ENV HOME=/tmp`; prompt-runner options), so
 *      it discovers skills under `$HOME/.claude/skills/<name>/SKILL.md`. The
 *      Dockerfile flattens the repo `skills/<cat>/<name>/` tree to exactly that
 *      layout. We assert every expected skill dir is present there with a
 *      readable `SKILL.md`.
 *   2. Binary resolution. Each skill that ships an on-PATH command is probed
 *      `which`-style against `process.env.PATH`. ALL missing binaries are
 *      reported at once (not first-fail) so one rebuild fixes everything.
 *
 * Why a filesystem proxy for discovery (not a programmatic SDK enumeration):
 * the SDK only exposes a skills/commands listing on a *live, credentialed*
 * streaming `query` control session — far too heavy (and credential-coupled)
 * for a cheap preflight that must run before any agent. The SDK derives the
 * discovered set purely from the `$HOME/.claude/skills` tree, so that directory
 * is the authoritative source and the filesystem check is an exact proxy.
 *
 * Severity is environment-aware (see `classifyEnvironment`): a hard FAIL in the
 * production image, a loud WARNING in a local/dev checkout that simply has not
 * staged the skills/tools, so local work is never blocked by the gate.
 */

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { ErrorCode } from "../../types/errors.js";
import { err, ok, type Result } from "../../types/result.js";
import { PentestError } from "../error-handling.js";
import {
	expectedSkillNames,
	SKILL_BINARIES,
	skillsTreeFsRoot,
} from "./skill-catalog.js";

/** The dir the SDK reads with `settingSources:["user"]`: `$HOME/.claude/skills`. */
function skillDiscoveryDir(home: string): string {
	return path.join(home, ".claude", "skills");
}

/** True when `name` resolves to an executable file on the supplied PATH. */
async function isOnPath(name: string, pathEnv: string): Promise<boolean> {
	const entries = pathEnv.split(path.delimiter).filter(Boolean);
	for (const dir of entries) {
		const candidate = path.join(dir, name);
		try {
			// fs.access with X_OK matches `which`: an executable regular file.
			await fs.access(candidate, fs.constants.X_OK);
			return true;
		} catch {
			// Not here (or not executable) — keep scanning the rest of PATH.
		}
	}
	return false;
}

/** Whether `<discoveryDir>/<skill>/SKILL.md` exists and is a readable file. */
async function skillIsDiscovered(
	discoveryDir: string,
	skill: string,
): Promise<boolean> {
	try {
		const stat = await fs.stat(path.join(discoveryDir, skill, "SKILL.md"));
		return stat.isFile();
	} catch {
		return false;
	}
}

type EnvKind = "image" | "local";

/**
 * Classify the run as the production image vs. a local/dev checkout.
 *
 * The image bakes `HOME=/tmp` and materializes `/tmp/.claude/skills`. We treat
 * the run as the image when the discovery dir already exists; otherwise it is a
 * local checkout that never staged skills, where a missing tree must not block
 * iteration. This keeps the hard gate exactly where it matters (the deployed
 * Job) and downgrades it to a warning everywhere else.
 */
async function classifyEnvironment(discoveryDir: string): Promise<EnvKind> {
	try {
		const stat = await fs.stat(discoveryDir);
		if (stat.isDirectory()) return "image";
	} catch {
		// discovery dir absent
	}
	return "local";
}

interface DiscoveryFindings {
	expected: string[];
	missingSkills: string[];
	missingBinaries: { skill: string; binary: string }[];
}

/** Run both checks and collect every problem (never first-fail). */
async function collectFindings(
	discoveryDir: string,
	pathEnv: string,
	skillsTreeRoot?: string,
): Promise<DiscoveryFindings> {
	const expected = await expectedSkillNames(skillsTreeRoot);

	const missingSkills: string[] = [];
	const missingBinaries: { skill: string; binary: string }[] = [];

	for (const skill of expected) {
		if (!(await skillIsDiscovered(discoveryDir, skill))) {
			missingSkills.push(skill);
		}
		const binary = SKILL_BINARIES[skill];
		// `null` => methodology skill (authz-recipe) or a deliberately-deferred
		// tool whose binary the image does not ship (hydra): no PATH probe.
		if (binary && !(await isOnPath(binary, pathEnv))) {
			missingBinaries.push({ skill, binary });
		}
	}

	return { expected, missingSkills, missingBinaries };
}

/** Human-readable summary of what is missing, for logs and the error message. */
function describeFindings(findings: DiscoveryFindings): string {
	const parts: string[] = [];
	if (findings.missingSkills.length) {
		parts.push(
			`skills not discovered (${findings.missingSkills.length}): ${findings.missingSkills.join(", ")}`,
		);
	}
	if (findings.missingBinaries.length) {
		const list = findings.missingBinaries
			.map((m) => `${m.binary} (skill: ${m.skill})`)
			.join(", ");
		parts.push(
			`tool binaries missing from PATH (${findings.missingBinaries.length}): ${list}`,
		);
	}
	return parts.join("; ");
}

export interface ToolingDiscoveryOptions {
	/** Override `$HOME` (tests). Defaults to `process.env.HOME` / os.homedir(). */
	home?: string;
	/** Override `PATH` (tests). Defaults to `process.env.PATH`. */
	pathEnv?: string;
	/** Override the repo `skills/` tree root used to derive the expected set. */
	skillsTreeRoot?: string;
}

/**
 * Assert the agent runtime is fully provisioned: every expected skill is where
 * the SDK discovers skills, and every offensive tool binary resolves on PATH.
 *
 * Production image → hard FAIL (returns `err`). Local/dev checkout missing the
 * staged tree → loud WARNING (returns `ok`) so local work is not blocked.
 */
export async function validateToolingDiscovery(
	logger: ActivityLogger,
	opts: ToolingDiscoveryOptions = {},
): Promise<Result<void, PentestError>> {
	const home = opts.home ?? process.env.HOME ?? os.homedir();
	const pathEnv = opts.pathEnv ?? process.env.PATH ?? "";
	const discoveryDir = skillDiscoveryDir(home);

	logger.info("Checking skill discovery + tool binaries...", {
		discoveryDir,
		skillsTreeRoot: opts.skillsTreeRoot ?? skillsTreeFsRoot(),
	});

	const findings = await collectFindings(discoveryDir, pathEnv, opts.skillsTreeRoot);

	if (!findings.missingSkills.length && !findings.missingBinaries.length) {
		logger.info("Tooling discovery OK", {
			skills: findings.expected.length,
			discoveryDir,
		});
		return ok(undefined);
	}

	const summary = describeFindings(findings);
	const env = await classifyEnvironment(discoveryDir);

	if (env === "local") {
		// Local/dev checkout that never staged skills/tools. Warn loudly but do
		// not block: the production image is where this must be airtight.
		logger.warn(
			`Tooling discovery incomplete (local/dev — not blocking): ${summary}. ` +
				`In the production image every skill must be discoverable at ${discoveryDir} ` +
				`and every tool binary must be on PATH.`,
			{ ...findings, home, env },
		);
		return ok(undefined);
	}

	// Production image: the agents would silently lose tools — fail loudly.
	return err(
		new PentestError(
			`Agent runtime is under-provisioned: ${summary}. ` +
				`Expected ${findings.expected.length} skills discoverable under ${discoveryDir} ` +
				`(SDK settingSources:["user"], HOME=${home}) and their tool binaries on PATH. ` +
				`Rebuild the worker image (skills flatten + tools.lock) before scanning.`,
			"tool",
			false,
			{ ...findings, home, discoveryDir, env },
			ErrorCode.TOOLING_MISSING,
		),
	);
}
