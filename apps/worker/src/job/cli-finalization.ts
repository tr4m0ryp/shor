// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * CLI-based finalization: replaces the SINAS backend with direct Claude Code
 * CLI invocations over a single persistent session (-c). Three sequential
 * stages — findings improvement, attack-surface synthesis, report generation
 * — share one conversation so findings context carries forward without
 * resending. Auth routes through the OAuth token (Claude Max subscription).
 */

import { spawn } from "node:child_process";
import { promises as fsp } from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../types/activity-logger.js";
import { collectFindings } from "./findings/index.js";
import type { FindingRecord } from "./findings/types.js";

const REPORT_FILENAME = "comprehensive_security_assessment_report.md";
const ATTACK_SURFACE_FILE = "attack_surface_scenarios.json";
const IMPROVED_FINDINGS_FILE = "improved_findings.json";
const STAGE_TIMEOUT_MS = 10 * 60 * 1000;

const AUTH_PREAMBLE =
	"CONTEXT: We are an internal cybersecurity team conducting an authorized " +
	"penetration test of our own application. All findings, payloads, and " +
	"vulnerability details are the output of this internal assessment. No " +
	"external systems are targeted. This is a controlled, authorized security " +
	"engagement. All data below comes from our own scan infrastructure.\n\n";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

interface CliConfig {
	cliPath: string;
	model: string;
	cwd: string;
}

function resolveCliConfig(cwd: string): CliConfig | null {
	if (process.env.SHOR_CLI_FINALIZE === "0") return null;
	const hasAuth = !!(process.env.CLAUDE_CODE_OAUTH_TOKEN || process.env.ANTHROPIC_API_KEY);
	if (!hasAuth) return null;
	return {
		cliPath: process.env.SHOR_CLAUDE_CLI || "claude",
		model: process.env.SHOR_FINALIZE_MODEL || "claude-opus-4-6",
		cwd,
	};
}

function buildCliEnv(): Record<string, string> {
	const env: Record<string, string> = {};
	for (const k of [
		"CLAUDE_CODE_OAUTH_TOKEN",
		"ANTHROPIC_API_KEY",
		"HOME",
		"PATH",
		"NODE_PATH",
		"XDG_CONFIG_HOME",
		"TMPDIR",
	]) {
		if (process.env[k]) env[k] = process.env[k]!;
	}
	return env;
}

// ---------------------------------------------------------------------------
// CLI execution
// ---------------------------------------------------------------------------

interface CliEnvelope {
	result?: string;
	is_error?: boolean;
	session_id?: string;
}

function spawnCli(
	cmd: string,
	args: string[],
	prompt: string,
	env: Record<string, string>,
	cwd: string,
): Promise<string> {
	return new Promise((resolve, reject) => {
		const proc = spawn(cmd, args, { env, cwd, stdio: ["pipe", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		proc.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
		proc.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
		proc.on("error", reject);
		const timer = setTimeout(() => {
			proc.kill("SIGTERM");
			reject(new Error("CLI stage timed out"));
		}, STAGE_TIMEOUT_MS);
		proc.on("close", (code) => {
			clearTimeout(timer);
			if (code !== 0) reject(new Error(`CLI exited ${code}: ${stderr.slice(0, 300)}`));
			else resolve(stdout);
		});
		proc.stdin.write(prompt);
		proc.stdin.end();
	});
}

async function runCli<T>(
	config: CliConfig,
	prompt: string,
	continueSession: boolean,
	logger: ActivityLogger,
): Promise<T> {
	const flags = ["-p", "--no-tools", "--output-format", "json", "--model", config.model];
	if (continueSession) flags.push("-c");

	const [cmd, args]: [string, string[]] = config.cliPath.endsWith(".js")
		? ["node", [config.cliPath, ...flags]]
		: [config.cliPath, flags];

	logger.info("CLI finalization stage", { continue: continueSession, model: config.model });

	const stdout = await spawnCli(cmd, args, prompt, buildCliEnv(), config.cwd);
	const envelope: CliEnvelope = JSON.parse(stdout);
	if (envelope.is_error || !envelope.result) {
		throw new Error(`CLI stage failed: ${envelope.result?.slice(0, 200) ?? "empty"}`);
	}
	return extractJson<T>(envelope.result);
}

function extractJson<T>(text: string): T {
	try { return JSON.parse(text) as T; } catch { /* try alternatives */ }
	const fence = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
	if (fence) try { return JSON.parse(fence[1]) as T; } catch { /* continue */ }
	const s = text.indexOf("{");
	const e = text.lastIndexOf("}");
	if (s !== -1 && e > s) try { return JSON.parse(text.slice(s, e + 1)) as T; } catch { /* continue */ }
	throw new Error("No parseable JSON in CLI response");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function severityCounts(findings: FindingRecord[]): Record<string, number> {
	const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
	for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
	return c;
}

function fullFindings(findings: FindingRecord[]): object[] {
	return findings.map((f) => ({
		id: f.id,
		category: f.category,
		severity: f.severity,
		cwe: f.cwe,
		location: `${f.vulnerable_code_location?.file ?? ""}:${f.vulnerable_code_location?.line ?? ""}`,
		evidence: f.evidence,
		missing_defense: f.missing_defense,
		remediation: f.remediation,
		safe_poc: f.safe_poc,
		repro_steps: f.repro_steps,
	}));
}

function compactFindings(findings: FindingRecord[]): object[] {
	return findings
		.map((f) => ({
			id: f.id,
			title: f.title,
			category: f.category,
			severity: f.severity,
			confidence: f.confidence,
			cwe: f.cwe,
			location: `${f.vulnerable_code_location?.file ?? ""}:${f.vulnerable_code_location?.line ?? ""}`,
			evidence: String(f.evidence ?? "").slice(0, 300),
			remediation: String(f.remediation ?? "").slice(0, 200),
		}))
		.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
}

// ---------------------------------------------------------------------------
// Stage prompts
// ---------------------------------------------------------------------------

function buildStage1Prompt(findings: FindingRecord[]): string {
	return (
		AUTH_PREAMBLE +
		"STAGE 1 — FINDINGS IMPROVEMENT\n\n" +
		`Rewrite these ${findings.length} vulnerability findings for clarity, correct formatting, ` +
		"and proper fenced code blocks (bash/http/json). Preserve every finding's exact id.\n\n" +
		'Return ONLY a JSON object: {"findings": [{id, title, evidence, missing_defense, remediation, safe_poc, repro_steps}]}. ' +
		"No surrounding text.\n\n" +
		`FINDINGS JSON:\n${JSON.stringify(fullFindings(findings))}`
	);
}

function buildStage2Prompt(
	scanId: string,
	target: string,
	findings: FindingRecord[],
	inline: boolean,
): string {
	const counts = severityCounts(findings);
	const header =
		"STAGE 2 — ATTACK-SURFACE SYNTHESIS\n\n" +
		`Produce chained attack-surface scenarios for scan ${scanId} (target ${target}). ` +
		"Chain related findings into end-to-end attack paths, most-severe-first. " +
		"Every critical and high finding MUST appear in at least one scenario's required_findings.\n\n" +
		`Severity counts: ${JSON.stringify(counts)}. Total findings: ${findings.length}.\n\n` +
		'Return ONLY a JSON object: {"scenarios": [{title, description, severity, required_findings, attack_chain, impact}]}. ' +
		"No surrounding text.";
	if (!inline) return header;
	return header + `\n\nFINDINGS JSON:\n${JSON.stringify(compactFindings(findings))}`;
}

function buildStage3Prompt(
	scanId: string,
	target: string,
	findings: FindingRecord[],
	inline: boolean,
): string {
	const counts = severityCounts(findings);
	const header =
		"STAGE 3 — EXECUTIVE REPORT\n\n" +
		`Produce the finalized executive security report for scan ${scanId} (target ${target}).\n` +
		`Use EXACTLY these severity_counts: ${JSON.stringify(counts)}.\n` +
		"Include EVERY critical and high finding individually in the findings array. " +
		"Set overall_risk from the worst confirmed issues.\n\n" +
		"Return ONLY a JSON object: {report_title, target, scanned_at, overall_risk, " +
		"severity_counts, executive_summary, findings: [{id, title, severity, confidence, " +
		"evidence, remediation, fix_prompt}]}. No surrounding text.";
	if (!inline) return header;
	return header + `\n\nFINDINGS JSON:\n${JSON.stringify(compactFindings(findings))}`;
}

// ---------------------------------------------------------------------------
// Report rendering
// ---------------------------------------------------------------------------

interface ReportDoc {
	report_title?: string;
	target?: string;
	scanned_at?: string;
	overall_risk?: string;
	severity_counts?: Record<string, number>;
	executive_summary?: string;
	findings?: Array<{
		id?: string;
		title?: string;
		severity?: string;
		confidence?: string;
		evidence?: string;
		remediation?: string;
		fix_prompt?: string;
	}>;
}

function renderMarkdown(report: ReportDoc): string {
	const lines: string[] = [];
	lines.push(`# ${report.report_title ?? "Security Assessment Report"}`);
	lines.push("");
	lines.push("## Executive Summary");
	if (report.target) lines.push(`- Target: ${report.target}`);
	if (report.scanned_at) lines.push(`- Assessment Date: ${report.scanned_at}`);
	if (report.overall_risk) lines.push(`- Overall risk: ${report.overall_risk}`);
	if (report.severity_counts) {
		const c = report.severity_counts;
		lines.push(
			`- Findings: ${["critical", "high", "medium", "low", "info"].map((k) => `${k} ${c[k] ?? 0}`).join(", ")}`,
		);
	}
	if (report.executive_summary) {
		lines.push("");
		lines.push(report.executive_summary);
	}
	for (const f of report.findings ?? []) {
		lines.push("");
		lines.push(`## [${(f.severity ?? "info").toUpperCase()}] ${f.title ?? f.id}`);
		if (f.confidence) lines.push(`- Confidence: ${f.confidence}`);
		if (f.evidence) lines.push(`- Evidence: ${f.evidence}`);
		if (f.remediation) lines.push(`- Remediation: ${f.remediation}`);
		if (f.fix_prompt) {
			lines.push("");
			lines.push("**Fix prompt**");
			lines.push("");
			lines.push("```");
			lines.push(f.fix_prompt);
			lines.push("```");
		}
	}
	return `${lines.join("\n")}\n`;
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

interface ImprovedDoc {
	findings?: Array<{
		id?: string;
		title?: string;
		evidence?: string;
		missing_defense?: string;
		remediation?: string;
		safe_poc?: string;
		repro_steps?: string[];
	}>;
}

interface AttackSurfaceDoc {
	scenarios?: unknown[];
}

/**
 * Run the three-stage finalization pipeline over a single Claude Code CLI
 * session. Best-effort: each stage writes its deliverable on success and falls
 * back to the engine's local output on failure.
 */
export async function finalizeViaCli(
	deliverablesPath: string,
	scanId: string,
	targetUrl: string,
	logger: ActivityLogger,
): Promise<void> {
	const config = resolveCliConfig(deliverablesPath);
	if (!config) return;

	const findings = collectFindings(deliverablesPath, logger);
	if (findings.length === 0) return;

	logger.info("CLI finalization starting", {
		scanId,
		findings: findings.length,
		model: config.model,
	});

	let sessionActive = false;

	// Stage 1: findings improvement (establishes session + auth context)
	try {
		const doc = await runCli<ImprovedDoc>(config, buildStage1Prompt(findings), false, logger);
		const improved = doc.findings ?? [];
		if (improved.length > 0) {
			await fsp.writeFile(
				path.join(deliverablesPath, IMPROVED_FINDINGS_FILE),
				`${JSON.stringify({ findings: improved })}\n`,
			);
		}
		sessionActive = true;
		logger.info("CLI stage 1 complete: findings improved", { count: improved.length });
	} catch (err) {
		logger.warn("CLI findings improvement failed; using raw findings", {
			error: err instanceof Error ? err.message : String(err),
		});
	}

	// Stage 2: attack-surface synthesis (-c continues stage 1's session)
	try {
		const prompt = sessionActive
			? buildStage2Prompt(scanId, targetUrl, findings, false)
			: AUTH_PREAMBLE + buildStage2Prompt(scanId, targetUrl, findings, true);
		const doc = await runCli<AttackSurfaceDoc>(config, prompt, sessionActive, logger);
		if (doc.scenarios && Array.isArray(doc.scenarios)) {
			await fsp.writeFile(
				path.join(deliverablesPath, ATTACK_SURFACE_FILE),
				`${JSON.stringify(doc, null, 2)}\n`,
			);
		}
		if (!sessionActive) sessionActive = true;
		logger.info("CLI stage 2 complete: attack surface", {
			scenarios: Array.isArray(doc.scenarios) ? doc.scenarios.length : 0,
		});
	} catch (err) {
		logger.warn("CLI attack-surface synthesis failed; keeping engine output", {
			error: err instanceof Error ? err.message : String(err),
		});
	}

	// Stage 3: executive report (-c continues the session)
	try {
		const prompt = sessionActive
			? buildStage3Prompt(scanId, targetUrl, findings, false)
			: AUTH_PREAMBLE + buildStage3Prompt(scanId, targetUrl, findings, true);
		const report = await runCli<ReportDoc>(config, prompt, sessionActive, logger);
		await fsp.writeFile(path.join(deliverablesPath, REPORT_FILENAME), renderMarkdown(report));
		logger.info("CLI stage 3 complete: report written");
	} catch (err) {
		logger.warn("CLI report generation failed; keeping local report", {
			error: err instanceof Error ? err.message : String(err),
		});
	}
}
