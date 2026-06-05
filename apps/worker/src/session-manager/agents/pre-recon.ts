// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from "zx";

import {
	buildManifestFromRepo,
	isTierCovered,
	readManifest,
	writeManifest,
} from "../../job/coverage/index.js";
import type { CoverageManifest } from "../../job/coverage/index.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentDefinition, AgentValidator } from "../../types/index.js";

export const preReconAgent: AgentDefinition = {
	name: "pre-recon",
	displayName: "Pre-recon agent",
	prerequisites: [],
	promptTemplate: "pre-recon-code",
	deliverableFilename: "pre_recon_deliverable.md",
	modelTier: "large",
};

const DELIVERABLE = "pre_recon_deliverable.md";

/**
 * Derive the cloned-repo root from the deliverables directory. Deliverables
 * live under `<repoPath>/.storron/deliverables[/...]`, so the repo root is the
 * parent of the nearest `.storron` ancestor. Falls back to two levels up (the
 * default `.storron/deliverables` depth) when no `.storron` segment is found.
 */
function repoRootFromDeliverables(sourceDir: string): string {
	const parts = sourceDir.split(path.sep);
	const idx = parts.lastIndexOf(".storron");
	if (idx > 0) return parts.slice(0, idx).join(path.sep) || path.sep;
	return path.resolve(sourceDir, "..", "..");
}

/**
 * Always emit `coverage_manifest.json` (T1 shared contract) into the
 * deliverables dir. Prefer the manifest the pre-recon agent confirmed/overrode
 * in its deliverable; otherwise seed it from a deterministic classification of
 * the cloned repo; otherwise (black-box / no source) synthesize a no-repo
 * manifest with every tier absent. Best-effort — never throws.
 *
 * Returns the emitted manifest so the caller can tailor the synthesized
 * deliverable note (client-only vs. black-box).
 */
async function emitCoverageManifest(
	sourceDir: string,
	logger: ActivityLogger,
): Promise<CoverageManifest> {
	// 1. Respect an agent-authored manifest if one is already present.
	const existing = await readManifest(sourceDir);
	if (existing) {
		logger.info("coverage manifest present (agent-authored); leaving as-is", {
			tiers: existing.tiers,
		});
		return existing;
	}

	// 2. Seed from a deterministic walk of the cloned repository.
	const repoRoot = repoRootFromDeliverables(sourceDir);
	let manifest = await buildManifestFromRepo(repoRoot);

	// 3. No analyzable source (black-box scan) → synthesize an all-absent manifest.
	if (!manifest) {
		manifest = {
			tiers: {
				frontend: "absent",
				backend: "absent",
				config: "absent",
				schema: "absent",
				tests: "absent",
			},
			observedLiveOnly: [],
			notes:
				"No analyzable source in the upload (black-box scan / empty repo). " +
				"Every tier is an UNSEEN trust boundary; downstream agents operate " +
				"against the running application only.",
		};
	}

	try {
		const file = await writeManifest(sourceDir, manifest);
		logger.info("Wrote coverage manifest", {
			file,
			tiers: manifest.tiers,
			clientOnly:
				isTierCovered(manifest, "frontend") &&
				!isTierCovered(manifest, "backend"),
		});
	} catch (err) {
		logger.warn("Failed to write coverage manifest (continuing)", {
			error: err instanceof Error ? err.message : String(err),
		});
	}
	return manifest;
}

/**
 * Validate the pre-recon code-analysis deliverable, degrading gracefully when it
 * is absent, and ALWAYS emit the coverage manifest.
 *
 * Pre-recon is a SOURCE-CODE agent. On a black-box scan (no repository) — or a
 * repo with no analyzable source — it has nothing to analyze, and the flash model
 * sometimes writes a `coverage_check.md` summary instead of the required
 * deliverable. Hard-failing here aborts the ENTIRE scan at agent 1/14, even
 * though the downstream live-target (DAST) agents could run fine. So, mirroring
 * the vuln-agents' `ensureQueueFile` pattern, synthesize a minimal deliverable
 * (seeded from whatever the agent did produce) and pass, instead of crashing.
 *
 * The same degrade path now also covers "repo present but client-tier only": the
 * coverage manifest records `backend: absent`, and the synthesized note (when we
 * have to write one) says so explicitly — a live backend is an unseen trust
 * boundary, not analyzed source.
 */
export const preReconValidator: AgentValidator = async (
	sourceDir: string,
	logger: ActivityLogger,
): Promise<boolean> => {
	// Coverage manifest is emitted on EVERY path (deliverable present or not).
	const manifest = await emitCoverageManifest(sourceDir, logger);

	const deliverable = path.join(sourceDir, DELIVERABLE);
	if (await fs.pathExists(deliverable)) return true;

	const clientOnly =
		isTierCovered(manifest, "frontend") &&
		!isTierCovered(manifest, "backend");

	const coverage = path.join(sourceDir, "coverage_check.md");
	const notes = (await fs.pathExists(coverage)) ? await fs.readFile(coverage, "utf8") : "";

	const scopeNote = clientOnly
		? `The uploaded repository classifies as CLIENT-TIER ONLY (frontend present, ` +
			`no server framework/route handlers/ORM in source). Any backend reachable ` +
			`from the live target is an UNSEEN trust boundary — its source was not ` +
			`provided. Proceeding with live-target reconnaissance; downstream agents ` +
			`probe the running application for that unseen surface.`
		: `No source-code deliverable was produced. This is a black-box scan (no ` +
			`repository was provided) or the repository contained no analyzable source. ` +
			`Proceeding with live-target reconnaissance; downstream agents operate ` +
			`against the running application.`;

	const synthesized =
		`# Pre-recon Code Analysis\n\n` +
		`${scopeNote}\n\n` +
		(notes ? `## Coverage notes\n\n${notes}\n` : "");
	await fs.writeFile(deliverable, synthesized);
	logger.warn(
		clientOnly
			? "pre-recon deliverable missing; repo is client-tier only — synthesized a placeholder noting the unseen backend trust boundary so the scan continues"
			: "pre-recon deliverable missing (black-box / no source); synthesized a placeholder so the scan continues",
	);
	return true;
};
