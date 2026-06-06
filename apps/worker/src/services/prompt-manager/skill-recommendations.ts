// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Per-agent skill recommendations (soft scoping).
 *
 * Every agent can still discover all skills (progressive disclosure via
 * `~/.claude/skills`); this just appends a "recommended skills" footer to each
 * agent's prompt so the model is steered toward the tools that fit its attack
 * surface without being hard-restricted from reaching for another when needed.
 *
 * Keyed by prompt-template name (the value loaded by `loadPrompt`, e.g.
 * `vuln-injection`, `pre-recon-code`). Names mirror the repo `skills/<cat>/<name>`
 * dirs. Synthesis agents (report, attack-surface) get no offensive tools.
 */

const RECON = [
	"httpx", "katana", "naabu", "nmap", "subfinder", "dnsx", "gau",
	"waybackurls", "paramspider", "arjun", "wafw00f", "ffuf", "nuclei", "kxss",
];
const STATIC = ["semgrep", "gitleaks", "osv-scanner", "trufflehog"];

export const RECOMMENDED: Readonly<Record<string, readonly string[]>> = {
	"pre-recon-code": STATIC,
	recon: RECON,
	"vuln-injection": ["sqlmap", "commix", "nosqli", "arjun", "paramspider", "ffuf", "semgrep", "interactsh-client"],
	"exploit-injection": ["sqlmap", "commix", "nosqli", "interactsh-client"],
	"vuln-xss": ["dalfox", "kxss", "xsstrike", "arjun", "paramspider", "semgrep"],
	"exploit-xss": ["dalfox", "kxss", "xsstrike", "playwright"],
	"vuln-auth": ["jwt_tool", "hydra", "semgrep"],
	"exploit-auth": ["hydra", "jwt_tool", "generate-totp", "playwright"],
	"vuln-ssrf": ["ssrfmap", "interactsh-client", "semgrep"],
	"exploit-ssrf": ["ssrfmap", "interactsh-client", "playwright"],
	"vuln-authz": ["authz-recipe", "jwt_tool", "semgrep"],
	"exploit-authz": ["authz-recipe", "jwt_tool", "generate-totp", "playwright"],
	"vuln-logic": ["semgrep", "arjun", "httpx"],
	"screen-logic": ["ffuf", "httpx", "playwright"],
	"exploit-logic": ["ffuf", "jwt_tool", "httpx", "playwright"],
	"vuln-misconfig-web": ["semgrep", "nuclei", "httpx"],
	"screen-misconfig-web": ["nuclei", "httpx", "jwt_tool"],
	"exploit-misconfig-web": ["nuclei", "httpx", "jwt_tool", "playwright"],
};

/**
 * The "recommended skills" markdown footer for an agent, or "" when the agent
 * (synthesis / unknown) has no recommendations. `loadPrompt` appends this.
 *
 * Rendered as an explicit TOOL CHECKLIST the agent seeds into its TodoWrite plan
 * (one todo per applicable tool, each resolved `ran` or `skipped` with a
 * one-line reason), plus breadth-before-depth and justify-every-skip rules. This
 * is the cheap prevention layer that keeps the coverage gate from firing; it
 * complements the gate, it does not replace it.
 */
export function recommendedSkillsSection(promptName: string): string {
	const skills = RECOMMENDED[promptName];
	if (!skills || skills.length === 0) return "";
	const checklist = skills
		.map((s) => `- [ ] \`${s}\` — ran | skipped: <one-line reason>`)
		.join("\n");
	return [
		"",
		"## Tool checklist for this agent (seed into TodoWrite)",
		"",
		"These skills fit this agent's attack surface. Seed ONE TodoWrite item per",
		"applicable tool below, then resolve each as either `ran` or",
		"`skipped: <one-line reason>` before you finish the phase. Read a skill's",
		"`SKILL.md` for usage. All other skills stay available if a finding genuinely",
		"calls for one — this list is the floor, not the ceiling.",
		"",
		checklist,
		"",
		"**Breadth before depth.** Complete the surface sweep across the applicable",
		"tools above — at least attempt each, or justify the skip — BEFORE deep-diving",
		"any single finding. A shallow pass over the whole surface beats an exhaustive",
		"drill into the first hit while the rest goes untouched.",
		"",
		"**Justify every skip.** A tool left unrun needs a specific one-line reason",
		"(out of scope, not applicable to this stack, superseded by another tool's",
		"result). Running only one tool is a FAILED phase unless the rest are each",
		"explicitly justified. \"Did not get to it\" is not a reason.",
		"",
		"This is NOT a mandate to spray: honor this agent's own scope, per-host",
		"rate-limit, and minimum-impact rules above — pick the tool that fits each",
		"target rather than firing all of them at every input.",
		"",
	].join("\n");
}
