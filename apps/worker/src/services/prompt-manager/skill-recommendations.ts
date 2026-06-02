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

const RECOMMENDED: Readonly<Record<string, readonly string[]>> = {
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
};

/**
 * The "recommended skills" markdown footer for an agent, or "" when the agent
 * (synthesis / unknown) has no recommendations. `loadPrompt` appends this.
 */
export function recommendedSkillsSection(promptName: string): string {
	const skills = RECOMMENDED[promptName];
	if (!skills || skills.length === 0) return "";
	const list = skills.map((s) => `- \`${s}\``).join("\n");
	return [
		"",
		"## Recommended skills for this agent",
		"",
		"These skills fit this agent's attack surface — reach for them first. Read each",
		"skill's `SKILL.md` for usage. All other skills remain available if a finding",
		"genuinely calls for one.",
		"",
		list,
		"",
	].join("\n");
}
