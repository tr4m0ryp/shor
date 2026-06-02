// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Per-scan skill-usage tracker.
 *
 * The Cloud Run Job runs ONE scan with agents executing strictly in sequence,
 * so a process-scoped singleton cleanly attributes tool calls to the agent
 * currently running. The SDK message dispatcher reports every tool_use here; we
 * map the call to one of the known offensive-tool "skills" (by tool name, or by
 * the leading token of a Bash command) and remember which skills each agent
 * touched. The progress emitter reads this to show, live, which skills an agent
 * is using. An `onNewSkill` hook lets the emitter push an update the moment a
 * new skill first appears.
 */

/** The 31 skill names (mirror of the repo `skills/<category>/<name>` dirs). */
const KNOWN_SKILLS: ReadonlySet<string> = new Set([
	// recon
	"arjun", "dnsx", "ffuf", "gau", "httpx", "katana", "kxss", "naabu", "nmap",
	"nuclei", "paramspider", "subfinder", "wafw00f", "waybackurls",
	// exploit
	"authz-recipe", "commix", "dalfox", "generate-totp", "hydra",
	"interactsh-client", "jwt_tool", "nosqli", "playwright", "sqlmap", "ssrfmap",
	"sstimap", "xsstrike",
	// static-analysis
	"gitleaks", "osv-scanner", "semgrep", "trufflehog",
]);

/** Normalize a Bash leading token (strip path, drop a `.py`/`.sh` suffix). */
function normalizeToken(tok: string): string {
	const base = tok.split("/").pop() ?? tok;
	return base.replace(/\.(py|sh|js)$/, "");
}

/**
 * Extract the skill a tool call exercises, or null. Direct tool name match
 * wins (e.g. a future `Skill` tool); otherwise parse a Bash command's first
 * meaningful token (skipping `sudo`/env-assignments) and match a known skill.
 */
function skillForToolUse(toolName: string, params: Record<string, unknown>): string | null {
	const direct = normalizeToken(toolName);
	if (KNOWN_SKILLS.has(direct)) return direct;
	if (toolName === "Skill" && typeof params.name === "string" && KNOWN_SKILLS.has(params.name)) {
		return params.name;
	}
	if (toolName !== "Bash") return null;
	const cmd = typeof params.command === "string" ? params.command : "";
	if (!cmd) return null;
	for (const raw of cmd.trim().split(/\s+/)) {
		if (raw === "sudo" || raw.includes("=")) continue; // skip sudo + VAR=val prefixes
		const tok = normalizeToken(raw);
		if (KNOWN_SKILLS.has(tok)) return tok;
		break; // only the command's first real token names the tool
	}
	return null;
}

class SkillTracker {
	private readonly byAgent = new Map<string, Set<string>>();
	/** Fired (with the agent + skill) the first time an agent uses a new skill. */
	onNewSkill: ((agent: string, skill: string) => void) | null = null;

	/** Record a tool_use against `agent` if it maps to a known skill. Attributing
	 *  by explicit agent (not a global "current") keeps it correct when agents
	 *  run concurrently. */
	record(agent: string, toolName: string, params: Record<string, unknown>): void {
		if (!agent) return;
		const skill = skillForToolUse(toolName, params);
		if (!skill) return;
		let set = this.byAgent.get(agent);
		if (!set) {
			set = new Set();
			this.byAgent.set(agent, set);
		}
		if (set.has(skill)) return;
		set.add(skill);
		this.onNewSkill?.(agent, skill);
	}

	/** Skills used by one agent, in first-seen order. */
	skillsFor(agent: string): string[] {
		return [...(this.byAgent.get(agent) ?? [])];
	}

	/** Full agent → skills map (only agents that used ≥1 skill). */
	all(): Record<string, string[]> {
		const out: Record<string, string[]> = {};
		for (const [agent, set] of this.byAgent) {
			if (set.size) out[agent] = [...set];
		}
		return out;
	}
}

/** Process-scoped singleton (one scan per Job process). */
export const skillTracker = new SkillTracker();
