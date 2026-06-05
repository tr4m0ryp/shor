// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Skill catalog for the tooling-discovery preflight.
 *
 * Two responsibilities:
 *   1. Derive the EXPECTED skill set from the repo `skills/` tree at runtime —
 *      never a hardcoded count — so a renamed or added skill cannot silently
 *      drift past the check.
 *   2. Map each skill to the binary/wrapper it exercises on PATH (or `null`
 *      when the skill ships no own command).
 *
 * The map's keys are also the canonical skill set; a unit test asserts they
 * equal the tree-derived names, so adding a skill dir without updating this map
 * (or vice-versa) fails CI.
 */

import { promises as fs } from "node:fs";
import path from "node:path";

/**
 * Skill → on-PATH command, or `null` when the skill has no binary of its own.
 *
 * Most names map 1:1 (Go binaries, venv console scripts). The wrappers the
 * Dockerfile lays down under /usr/local/bin keep the same name as the skill
 * dir (`sqlmap`, `commix`, `sstimap`, `xsstrike`, `ssrfmap`, `jwt_tool`,
 * `generate-totp`). Three skills carry `null`:
 *   - `authz-recipe` — a broken-access-control METHODOLOGY (its own SKILL.md
 *     says there is no drop-in CLI; it drives curl + playwright + ffuf).
 *   - `git-security-history` — a historical-exploit-seeding RECIPE that ships
 *     its own bundled scripts (`mine.sh` + `assemble.py`) in the skill dir and
 *     drives only base-image tools (`git` + `python3`); it lays down no command
 *     of its own on PATH, so probing PATH for it would be a false alarm.
 *   - `hydra` — documented as a skill but DEFERRED from the image (README
 *     "DEFAULT-marked tools … NOT in this image"; absent from tools.lock and
 *     both Dockerfiles). The skill doc ships; the binary is intentionally not
 *     present, so probing PATH for it would be a false alarm.
 */
export const SKILL_BINARIES: Readonly<Record<string, string | null>> = {
	// recon
	arjun: "arjun",
	dnsx: "dnsx",
	ffuf: "ffuf",
	gau: "gau",
	httpx: "httpx",
	katana: "katana",
	kxss: "kxss",
	naabu: "naabu",
	nmap: "nmap",
	nuclei: "nuclei",
	paramspider: "paramspider",
	subfinder: "subfinder",
	wafw00f: "wafw00f",
	waybackurls: "waybackurls",
	// exploit
	"authz-recipe": null, // methodology, no CLI
	commix: "commix",
	dalfox: "dalfox",
	"generate-totp": "generate-totp",
	hydra: null, // deferred: skill doc present, binary not shipped
	"interactsh-client": "interactsh-client",
	jwt_tool: "jwt_tool",
	nosqli: "nosqli",
	playwright: "playwright",
	sqlmap: "sqlmap",
	ssrfmap: "ssrfmap",
	sstimap: "sstimap",
	xsstrike: "xsstrike",
	// static-analysis
	"git-security-history": null, // bundled recipe (git + python3), no own CLI
	gitleaks: "gitleaks",
	"osv-scanner": "osv-scanner",
	semgrep: "semgrep",
	trufflehog: "trufflehog",
};

/** Skill names from the binary map — the canonical expected set fallback. */
const CATALOG_SKILL_NAMES: readonly string[] = Object.keys(SKILL_BINARIES);

/**
 * Repo `skills/` tree root, resolved from this compiled file's location:
 * dist/services/preflight/skill-catalog.js → repo root → `skills/`.
 *
 * Present in a source checkout; ABSENT in the runtime image (the Dockerfile
 * flattens the tree into `$HOME/.claude/skills` and deletes the source). When
 * absent, `expectedSkillNames` falls back to the catalog map keys.
 */
export function skillsTreeFsRoot(): string {
	// import.meta.dirname = .../dist/services/preflight → up 3 = package root
	// (apps/worker); up 5 = repo root. The repo `skills/` dir lives at repo root.
	return path.resolve(import.meta.dirname, "..", "..", "..", "..", "skills");
}

/** Recursively collect the dir name of every `SKILL.md` under `root`. */
async function findSkillDirs(root: string): Promise<string[]> {
	const found: string[] = [];
	async function walk(dir: string): Promise<void> {
		let entries: import("node:fs").Dirent[];
		try {
			entries = await fs.readdir(dir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const entry of entries) {
			const full = path.join(dir, entry.name);
			if (entry.isDirectory()) {
				await walk(full);
			} else if (entry.isFile() && entry.name === "SKILL.md") {
				found.push(path.basename(dir));
			}
		}
	}
	await walk(root);
	return found;
}

/**
 * The expected skill set, derived from the repo `skills/` tree when reachable.
 *
 * Source checkout → names come from the tree (authoritative; resists drift).
 * Runtime image (tree flattened away) → falls back to the catalog map keys,
 * which the test pins to the tree. Always sorted + de-duplicated.
 */
export async function expectedSkillNames(treeRoot?: string): Promise<string[]> {
	const root = treeRoot ?? skillsTreeFsRoot();
	const fromTree = await findSkillDirs(root);
	const names = fromTree.length ? fromTree : [...CATALOG_SKILL_NAMES];
	return [...new Set(names)].sort();
}
