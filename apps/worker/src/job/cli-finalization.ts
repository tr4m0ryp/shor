// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * CLI-based finalization: replaces the SINAS backend with direct Claude Code
 * CLI invocations over a single persistent session (-c). Three sequential
 * stages — findings improvement, attack-surface synthesis, report generation
 * — share one conversation so findings context carries forward without
 * resending. Auth routes through the OAuth token (Claude Max subscription).
 */

import { spawn } from "node:child_process";
import { promises as fsp, readFileSync } from "node:fs";
import path from "node:path";
import { PROMPTS_DIR } from "../paths.js";
import type { ActivityLogger } from "../types/activity-logger.js";
import { dedupAndCollapse } from "./findings/dedup-collapse.js";
import { collectFindings } from "./findings/index.js";
import { flagBoilerplateRemediation } from "./findings/remediation-guard.js";
import type { FindingRecord } from "./findings/types.js";

const REPORT_FILENAME = "comprehensive_security_assessment_report.md";
const REPORT_JSON_FILE = "report.json";
const ATTACK_SURFACE_FILE = "attack_surface_scenarios.json";
const ATTACK_SURFACE_MD = "attack_surface_scenarios.md";
const IMPROVED_FINDINGS_FILE = "improved_findings.json";
const STAGE_TIMEOUT_MS = 10 * 60 * 1000;
// Stage 1 (findings improvement) inlines the FULL prose of each finding and asks the
// model to rewrite every one. Sending many at once overran the model's max-tokens and
// made `claude -p` exit 1 (so findings were never improved). Empirically 2 findings/call
// succeeds while 8 overruns — so improve in SMALL batches, run several CONCURRENTLY (the
// model is slow, ~90s/call), and retry a batch once. One bad batch leaves only its
// findings raw.
const STAGE1_BATCH_SIZE = 2;
const STAGE1_CONCURRENCY = 4;

// Full SINAS-era finalize prompts (recovered from infra/sinas/agents). Loaded
// from prompts/finalize/*.txt rather than inlined — they carry fenced-code
// examples and long-form instructions that don't survive TS template literals.
// Cached on first read; these files ship alongside the engine prompt templates.
const FINALIZE_PROMPT_DIR = path.join(PROMPTS_DIR, "finalize");
const promptCache = new Map<string, string>();
function finalizePrompt(name: string): string {
	const cached = promptCache.get(name);
	if (cached !== undefined) return cached;
	const text = readFileSync(path.join(FINALIZE_PROMPT_DIR, name), "utf8").trim();
	promptCache.set(name, text);
	return text;
}

const AUTH_PREAMBLE =
	"CONTEXT: We are an internal cybersecurity team conducting an authorized " +
	"penetration test of our own application. All findings, payloads, and " +
	"vulnerability details are the output of this internal assessment. No " +
	"external systems are targeted. This is a controlled, authorized security " +
	"engagement. All data below comes from our own scan infrastructure.\n\n";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface CliConfig {
	cliPath: string;
	model: string;
	cwd: string;
}

export function resolveCliConfig(cwd: string): CliConfig | null {
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
	const flags = ["-p", "--output-format", "json", "--model", config.model];
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
	if (fence?.[1]) try { return JSON.parse(fence[1]) as T; } catch { /* continue */ }
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

// Each stage is SELF-CONTAINED: the caller prepends AUTH_PREAMBLE and the
// findings are inlined into every stage's prompt, so no stage depends on a `-c`
// session carrying context from a prior one (a stage failure never cascades).
// Each stage also appends an explicit JSON-output contract, because the CLI
// path has no equivalent of the structured-output schema the SINAS agents used.

function buildStage1Prompt(findings: FindingRecord[]): string {
	return (
		`${finalizePrompt("findings-improver.txt")}\n\n` +
		'Return ONLY a JSON object — no prose before or after — of the form ' +
		'{"findings": [{"id", "title", "evidence", "missing_defense", "remediation", ' +
		'"safe_poc", "repro_steps"}]}, containing EVERY finding keyed by its exact id.\n\n' +
		`FINDINGS JSON:\n${JSON.stringify(fullFindings(findings))}`
	);
}

function buildStage2Prompt(scanId: string, target: string, findings: FindingRecord[]): string {
	const counts = severityCounts(findings);
	return (
		`${finalizePrompt("attack-surface.txt")}\n\n` +
		`This is scan ${scanId}, target ${target}. ` +
		`Severity counts over all findings: ${JSON.stringify(counts)}; total findings: ${findings.length}.\n\n` +
		'Return ONLY a JSON object — no prose before or after — of the form ' +
		'{"scenarios": [{"id", "title", "severity", "required_findings", "explanation", ' +
		'"kill_chain", "how_to_reproduce", "business_impact", "remediation", "claude_code_prompt"}]}. ' +
		// Bound the output: synthesizing a scenario per finding overruns the model's
		// max-tokens and makes the CLI exit non-zero (the attack surface is then lost).
		"Synthesize ONLY the most significant attack scenarios, most-dangerous-first — at most 12 — " +
		"each consolidating the related findings via `required_findings`." +
		`\n\nFINDINGS JSON:\n${JSON.stringify(compactFindings(findings))}`
	);
}

function buildStage3Prompt(scanId: string, target: string, findings: FindingRecord[]): string {
	const counts = severityCounts(findings);
	return (
		`${finalizePrompt("report.txt")}\n\n` +
		`This is scan ${scanId}, target ${target}. ` +
		`Use EXACTLY these severity_counts (do not recompute): ${JSON.stringify(counts)}.\n\n` +
		'Return ONLY a JSON object — no prose before or after — of the form ' +
		'{"report_title", "target", "scanned_at", "overall_risk", "severity_counts", ' +
		'"executive_summary", "findings": [{"id", "title", "severity", "confidence", ' +
		'"evidence", "remediation", "fix_prompt"}]}.' +
		`\n\nFINDINGS JSON:\n${JSON.stringify(compactFindings(findings))}`
	);
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

interface AttackScenario {
	id?: string;
	title?: string;
	severity?: string;
	required_findings?: string[];
	explanation?: string;
	kill_chain?: string[];
	how_to_reproduce?: string[];
	business_impact?: string;
	remediation?: string;
	claude_code_prompt?: string;
}

interface AttackSurfaceDoc {
	scenarios?: AttackScenario[];
}

function renderAttackSurfaceMarkdown(doc: AttackSurfaceDoc): string {
	const scenarios = (doc.scenarios ?? []).filter(
		(s): s is AttackScenario => !!s && typeof s === "object",
	);
	const lines: string[] = ["# Attack Surface", ""];
	if (scenarios.length === 0) {
		lines.push("_No attack-surface scenarios were synthesized._");
		return `${lines.join("\n")}\n`;
	}
	const numbered = (label: string, items?: string[]): void => {
		if (!items?.length) return;
		lines.push(`**${label}**`, "");
		items.forEach((step, i) => lines.push(`${i + 1}. ${step}`));
		lines.push("");
	};
	scenarios.forEach((s, idx) => {
		const sev = (s.severity ?? "info").toUpperCase();
		lines.push(`## ${idx + 1}. [${sev}] ${s.title ?? s.id ?? "Untitled scenario"}`, "");
		if (s.explanation) lines.push(s.explanation, "");
		numbered("Kill chain", s.kill_chain);
		numbered("How to reproduce", s.how_to_reproduce);
		if (s.business_impact) lines.push(`**Business impact:** ${s.business_impact}`, "");
		if (s.remediation) lines.push(`**Remediation:** ${s.remediation}`, "");
		if (s.required_findings?.length) {
			lines.push(`**Findings used:** ${s.required_findings.join(", ")}`, "");
		}
		if (s.claude_code_prompt) {
			lines.push("**Fix prompt**", "", "```", s.claude_code_prompt, "```", "");
		}
	});
	return `${lines.join("\n")}\n`;
}

/**
 * Overlay stage-1's improved prose onto the raw findings, matched by id, so the
 * downstream stages reason over the cleaned title/evidence/remediation. Identity
 * fields (severity, category, cwe, location, id) are never touched. Returns the
 * original list unchanged when there is nothing to overlay.
 */
function overlayImproved(
	findings: FindingRecord[],
	improved: ImprovedDoc["findings"],
): FindingRecord[] {
	if (!improved?.length) return findings;
	const byId = new Map(improved.map((f) => [String(f.id), f]));
	const PROSE = ["title", "evidence", "missing_defense", "remediation", "safe_poc"] as const;
	return findings.map((f) => {
		const imp = byId.get(f.id);
		if (!imp) return f;
		const merged: FindingRecord = { ...f };
		for (const k of PROSE) {
			const v = imp[k];
			if (typeof v === "string" && v.length > 0) merged[k] = v;
		}
		if (Array.isArray(imp.repro_steps) && imp.repro_steps.length > 0) {
			merged.repro_steps = imp.repro_steps;
		}
		return merged;
	});
}

/** Result of the three-stage finalize, independent of any file IO. */
export interface FinalizeResult {
	/** Stage-1 rewritten prose, keyed by finding id (empty if stage 1 failed). */
	improved: NonNullable<ImprovedDoc["findings"]>;
	/** Raw findings overlaid with stage-1 prose — what stages 2-3 reasoned over. */
	effective: FindingRecord[];
	attackSurface?: AttackSurfaceDoc;
	attackSurfaceMarkdown?: string;
	report?: ReportDoc;
	reportMarkdown?: string;
}

/**
 * Run the three-stage finalize (findings improvement → attack-surface →
 * report) over the Claude Code CLI and RETURN the documents — no file IO, no
 * DB. Each stage is an INDEPENDENT, self-contained invocation: the authorization
 * preamble and the findings are inlined into every stage, so no stage relies on
 * a `-c` session carrying context from a prior one — a stage failing never
 * starves the next. Stages 2-3 reason over stage-1's improved prose when it
 * succeeded. This is the reusable core: `finalizeViaCli` wraps it with the
 * pipeline's deliverable-file writes; an off-pipeline rerun can feed findings
 * straight from the DB and persist however it likes.
 */
/**
 * Stage 1 in bounded batches: improve `STAGE1_BATCH_SIZE` findings per `claude -p`
 * call so neither the input nor the (rewrite-everything) output overruns the model's
 * limits. Returns the merged improved-prose entries across all batches; a batch that
 * throws contributes nothing (those findings stay raw) and never aborts the rest.
 */
/** Run one finalize stage with a single retry — guards a transient CLI exit / overrun. */
async function runCliRetry<T>(config: CliConfig, prompt: string, logger: ActivityLogger): Promise<T> {
	try {
		return await runCli<T>(config, prompt, false, logger);
	} catch (err) {
		logger.warn("CLI stage failed; retrying once", {
			error: err instanceof Error ? err.message : String(err),
		});
		await new Promise((r) => setTimeout(r, 4000));
		return runCli<T>(config, prompt, false, logger);
	}
}

async function improveFindingsBatched(
	findings: FindingRecord[],
	config: CliConfig,
	logger: ActivityLogger,
): Promise<NonNullable<ImprovedDoc["findings"]>> {
	const batches: FindingRecord[][] = [];
	for (let i = 0; i < findings.length; i += STAGE1_BATCH_SIZE) {
		batches.push(findings.slice(i, i + STAGE1_BATCH_SIZE));
	}
	const out: NonNullable<ImprovedDoc["findings"]> = [];
	let next = 0;
	const worker = async (): Promise<void> => {
		while (next < batches.length) {
			const mine = next++;
			const batch = batches[mine];
			if (!batch) continue;
			for (let attempt = 1; attempt <= 2; attempt += 1) {
				try {
					const doc = await runCli<ImprovedDoc>(
						config,
						AUTH_PREAMBLE + buildStage1Prompt(batch),
						false,
						logger,
					);
					const improved = doc.findings ?? [];
					out.push(...improved);
					logger.info("CLI stage 1 batch improved", {
						batch: mine + 1,
						of: batches.length,
						improved: improved.length,
					});
					break;
				} catch (err) {
					if (attempt === 2) {
						logger.warn("CLI stage 1 batch failed after retry; its findings stay raw", {
							batch: mine + 1,
							of: batches.length,
							size: batch.length,
							error: err instanceof Error ? err.message : String(err),
						});
					} else {
						await new Promise((r) => setTimeout(r, 4000));
					}
				}
			}
		}
	};
	await Promise.all(
		Array.from({ length: Math.min(STAGE1_CONCURRENCY, batches.length) }, () => worker()),
	);
	return out;
}

export async function finalizeFindings(
	findings: FindingRecord[],
	scanId: string,
	targetUrl: string,
	config: CliConfig,
	logger: ActivityLogger,
): Promise<FinalizeResult> {
	const result: FinalizeResult = { improved: [], effective: findings };

	// Stage 1: findings improvement, in bounded BATCHES (STAGE1_BATCH_SIZE). Stages
	// 2-3 then reason over `effective`, the raw findings overlaid with whatever prose
	// stage 1 cleaned up. A failed batch leaves only its findings raw (fail-open).
	const improved = await improveFindingsBatched(findings, config, logger);
	if (improved.length > 0) {
		result.improved = improved;
		result.effective = overlayImproved(findings, improved);
	}
	logger.info("CLI stage 1 complete: findings improved", {
		improved: improved.length,
		of: findings.length,
	});

	// T7: flag any remediation the improver left as the mapper's boilerplate template
	// (never ship a confirmed finding with non-actionable boilerplate silently).
	const boilerplateCount = flagBoilerplateRemediation(result.effective);
	if (boilerplateCount > 0) {
		logger.warn("Findings still carry boilerplate remediation after improve", {
			count: boilerplateCount,
		});
	}

	// T6: deterministically cluster + collapse duplicate findings so the attack
	// surface, report, and severity counts reason over ONE canonical finding per root
	// cause. Members are folded into `also_reported_as` — preserved, never dropped.
	const beforeCollapse = result.effective.length;
	result.effective = dedupAndCollapse(result.effective);
	if (result.effective.length < beforeCollapse) {
		logger.info("Collapsed duplicate findings for report", {
			from: beforeCollapse,
			to: result.effective.length,
		});
	}

	// Stage 2: attack-surface synthesis. Fresh session, findings re-inlined. One retry
	// (the synthesis output can transiently overrun max-tokens → CLI exit 1).
	try {
		const prompt = AUTH_PREAMBLE + buildStage2Prompt(scanId, targetUrl, result.effective);
		const doc = await runCliRetry<AttackSurfaceDoc>(config, prompt, logger);
		if (doc.scenarios && Array.isArray(doc.scenarios)) {
			result.attackSurface = doc;
			result.attackSurfaceMarkdown = renderAttackSurfaceMarkdown(doc);
		}
		logger.info("CLI stage 2 complete: attack surface", {
			scenarios: Array.isArray(doc.scenarios) ? doc.scenarios.length : 0,
		});
	} catch (err) {
		logger.warn("CLI attack-surface synthesis failed; keeping engine output", {
			error: err instanceof Error ? err.message : String(err),
		});
	}

	// Stage 3: executive report. Fresh session, findings re-inlined. One retry.
	try {
		const prompt = AUTH_PREAMBLE + buildStage3Prompt(scanId, targetUrl, result.effective);
		const report = await runCliRetry<ReportDoc>(config, prompt, logger);
		result.report = report;
		result.reportMarkdown = renderMarkdown(report);
		logger.info("CLI stage 3 complete: report written");
	} catch (err) {
		logger.warn("CLI report generation failed; keeping local report", {
			error: err instanceof Error ? err.message : String(err),
		});
	}

	return result;
}

/**
 * Pipeline finalize: read the engine's deliverables, run the three-stage CLI
 * finalize, and overwrite the deliverable files. Best-effort — each deliverable
 * is written only if its stage produced output, else the engine's local file
 * stands. No-op when CLI auth is absent or there are no findings.
 */
export async function finalizeViaCli(
	deliverablesPath: string,
	scanId: string,
	targetUrl: string,
	logger: ActivityLogger,
): Promise<void> {
	const config = resolveCliConfig(deliverablesPath);
	if (!config) return;

	const findings = await collectFindings(deliverablesPath, logger);
	if (findings.length === 0) return;

	logger.info("CLI finalization starting", {
		scanId,
		findings: findings.length,
		model: config.model,
	});

	const r = await finalizeFindings(findings, scanId, targetUrl, config, logger);

	if (r.improved.length > 0) {
		await fsp.writeFile(
			path.join(deliverablesPath, IMPROVED_FINDINGS_FILE),
			`${JSON.stringify({ findings: r.improved })}\n`,
		);
	}
	if (r.attackSurface) {
		await fsp.writeFile(
			path.join(deliverablesPath, ATTACK_SURFACE_FILE),
			`${JSON.stringify(r.attackSurface, null, 2)}\n`,
		);
		await fsp.writeFile(
			path.join(deliverablesPath, ATTACK_SURFACE_MD),
			r.attackSurfaceMarkdown ?? "",
		);
	}
	if (r.reportMarkdown) {
		await fsp.writeFile(path.join(deliverablesPath, REPORT_FILENAME), r.reportMarkdown);
	}
	// Persist the STRUCTURED report doc too: `emitFindings` reads it and posts it
	// through the findings sink so the dashboard's `/scans/:id/report` can serve it
	// from the DB (the old Sinas report store is decommissioned).
	if (r.report) {
		await fsp.writeFile(path.join(deliverablesPath, REPORT_JSON_FILE), `${JSON.stringify(r.report)}\n`);
	}
}

/** The structured-report deliverable filename, read by `emitFindings` (T-report). */
export const REPORT_JSON_FILENAME = REPORT_JSON_FILE;
