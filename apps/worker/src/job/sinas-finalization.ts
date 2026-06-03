// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Sinas-mode finalization (ADR-051 reporting handoff).
 *
 * When the user has connected Sinas, the Cloud Run Job offloads report
 * synthesis to their Sinas instance instead of relying on the local report
 * agent's output:
 *   1. the collected `FindingRecord`s are pushed to the `<ns>/findings` store,
 *   2. the `<ns>/finalizer` agent produces a structured report,
 *   3. that report is rendered to markdown — overwriting the local
 *      `comprehensive_security_assessment_report.md` — and persisted to the
 *      `<ns>/reports` store.
 *
 * Best-effort and non-fatal: with no credentials, an unreachable instance, or
 * any error, it leaves the locally-produced report in place and returns. It is
 * called between the pipeline and the dashboard findings POST in `runJob`.
 */

import { promises as fsp } from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../types/activity-logger.js";
import { collectFindings } from "./findings/index.js";
import type { FindingRecord } from "./findings/types.js";

const REPORT_FILENAME = "comprehensive_security_assessment_report.md";

interface SinasConnection {
	url: string;
	apiKey: string;
	namespace: string;
	/**
	 * Name of the finalizer agent under `<namespace>`. Configurable because
	 * via-12 has no agent PATCH/PUT: changing the finalizer's model means
	 * delete+recreate, and a soft-deleted name cannot be reused — so a model
	 * swap ships as a fresh agent name (e.g. `finalizer-opus`) selected here,
	 * with no engine rebuild. Defaults to `finalizer`.
	 */
	finalizerAgent: string;
	/** Attack-surface agent (same recreate-by-name constraint). Defaults to `attack-surface-opus`. */
	attackSurfaceAgent: string;
	/** Findings-improver agent (Sonnet) that rewrites raw findings for readability. */
	improverAgent: string;
}

/** Structured report returned by the Sinas finalizer agent (its output_schema). */
interface SinasReport {
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

/** Resolve the Sinas connection from env. Returns null when not connected. */
function resolveSinasConnection(): SinasConnection | null {
	const enabled = process.env.SINAS_ENABLED === "1";
	const url = process.env.SINAS_URL;
	const apiKey = process.env.SINAS_API_KEY;
	const namespace = process.env.SINAS_NAMESPACE ?? "pentest";
	const finalizerAgent = process.env.SINAS_FINALIZER_AGENT ?? "finalizer-opus-v2";
	const attackSurfaceAgent = process.env.SINAS_ATTACK_SURFACE_AGENT ?? "attack-surface-opus-v2";
	const improverAgent = process.env.SINAS_IMPROVER_AGENT ?? "findings-improver";
	if (!enabled || !url || !apiKey) return null;
	return { url: url.replace(/\/+$/, ""), apiKey, namespace, finalizerAgent, attackSurfaceAgent, improverAgent };
}

async function sinasFetch(
	conn: SinasConnection,
	method: string,
	apiPath: string,
	body?: unknown,
): Promise<Response> {
	const init: RequestInit = {
		method,
		headers: { "X-API-Key": conn.apiKey, "Content-Type": "application/json" },
	};
	if (body !== undefined) init.body = JSON.stringify(body);
	return fetch(`${conn.url}${apiPath}`, init);
}

/** Push each finding to the `<ns>/findings` store, keyed by its stable fingerprint. */
async function pushFindings(
	conn: SinasConnection,
	findings: FindingRecord[],
): Promise<number> {
	let pushed = 0;
	for (const f of findings) {
		const key = f.fingerprint || f.id;
		const res = await sinasFetch(
			conn,
			"POST",
			`/stores/${conn.namespace}/findings/states`,
			{ key, value: f, tags: [f.severity, f.status] },
		);
		if (res.ok) pushed++;
	}
	return pushed;
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * Build the finalizer message with the findings INLINE. The finalizer agent
 * otherwise retrieves findings via parallel `store_search` tool calls, which the
 * OpenRouter->Anthropic proxy rejects with "tool_use ids must be unique". Feeding
 * the data inline (and forbidding tools) sidesteps that, and listing only the
 * top-N severest findings keeps the response under the agent's max_tokens (the
 * full list is already in the dashboard).
 */
function buildFinalizerMessage(scanId: string, target: string, findings: FindingRecord[]): string {
	const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
	for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
	const compact = findings
		.map((f) => ({
			id: f.id,
			category: f.category,
			severity: f.severity,
			confidence: f.confidence,
			cwe: f.cwe,
			location: `${f.vulnerable_code_location?.file ?? ""}:${f.vulnerable_code_location?.line ?? ""}`,
			evidence: String(f.evidence ?? "").slice(0, 300),
			remediation: String(f.remediation ?? "").slice(0, 200),
		}))
		.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
	// No numeric cap: a fixed top-N silently dropped real critical/high issues.
	// Send all findings and require every critical/high to be reported individually;
	// the v2 agent's larger token budget makes this fit.
	return (
		`Produce the finalized executive report for scan ${scanId} (target ${target}).\n` +
		`Do NOT call any tools and do NOT read from the store — use ONLY the data in this message.\n` +
		`Use EXACTLY these severity_counts: ${JSON.stringify(counts)}.\n` +
		`Include EVERY critical and high finding INDIVIDUALLY in the "findings" array — do not cap or summarise them away. You may group medium/low/info (the counts already capture them). Set overall_risk from the worst confirmed issues.\n\n` +
		`FINDINGS JSON:\n${JSON.stringify(compact)}`
	);
}

/** Drive the finalizer agent over the chat stream and return its structured report. */
async function runFinalizer(
	conn: SinasConnection,
	scanId: string,
	target: string,
	findings: FindingRecord[],
): Promise<SinasReport> {
	const chatRes = await sinasFetch(
		conn,
		"POST",
		`/agents/${conn.namespace}/${conn.finalizerAgent}/chats`,
		{ title: `scan ${scanId}`, input: { scan_id: scanId, target } },
	);
	if (!chatRes.ok) throw new Error(`create chat failed: ${chatRes.status}`);
	const chat = (await chatRes.json()) as { id?: string };
	if (!chat.id) throw new Error("no chat id");

	const msgRes = await sinasFetch(
		conn,
		"POST",
		`/chats/${chat.id}/messages/stream`,
		{ content: buildFinalizerMessage(scanId, target, findings) },
	);
	if (!msgRes.ok) throw new Error(`finalizer message failed: ${msgRes.status}`);

	return parseFinalizerStream(await msgRes.text());
}

/**
 * Parse the SSE stream. The finalizer streams its JSON report as many small
 * `content` string deltas, so accumulate them and parse the assembled object at
 * the end. A whole-object `content` (non-streamed) is still handled. Surfaces
 * provider errors verbatim.
 */
function parseFinalizerStream(stream: string): SinasReport {
	let buf = "";
	let whole: SinasReport | null = null;
	for (const line of stream.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed.startsWith("data:")) continue;
		let evt: { type?: string; error?: string; content?: unknown };
		try {
			evt = JSON.parse(trimmed.slice(5).trim());
		} catch {
			continue;
		}
		if (evt.type === "error") throw new Error(`finalizer error: ${evt.error}`);
		const content = evt.content;
		if (typeof content === "string") buf += content;
		else if (typeof content === "object" && content !== null) whole = content as SinasReport;
	}
	let last = whole;
	if (!last && buf) {
		const s = buf.indexOf("{");
		const e = buf.lastIndexOf("}");
		if (s !== -1 && e > s) {
			try {
				last = JSON.parse(buf.slice(s, e + 1)) as SinasReport;
			} catch {
				/* truncated/invalid */
			}
		}
	}
	if (!last) throw new Error("finalizer returned no structured report");
	return last;
}

/** Render the structured report to the markdown the dashboard expects. */
function renderMarkdown(report: SinasReport): string {
	const lines: string[] = [];
	lines.push(`# ${report.report_title ?? "Security Assessment Report"}`);
	lines.push("");
	lines.push("## Executive Summary");
	if (report.target) lines.push(`- Target: ${report.target}`);
	if (report.scanned_at) lines.push(`- Assessment Date: ${report.scanned_at}`);
	if (report.overall_risk) lines.push(`- Overall risk: ${report.overall_risk}`);
	if (report.severity_counts) {
		const c = report.severity_counts;
		const order = ["critical", "high", "medium", "low", "info"];
		lines.push(`- Findings: ${order.map((k) => `${k} ${c[k] ?? 0}`).join(", ")}`);
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

/**
 * Offload finalization to the connected user's Sinas instance. Best-effort:
 * overwrites the local report on success, leaves it untouched on any failure.
 */
export async function finalizeViaSinas(
	deliverablesPath: string,
	scanId: string,
	targetUrl: string,
	logger: ActivityLogger,
): Promise<void> {
	const conn = resolveSinasConnection();
	if (!conn) return;
	logger.info("Sinas-mode finalization", { url: conn.url, ns: conn.namespace });
	try {
		const findings = collectFindings(deliverablesPath, logger);
		const pushed = await pushFindings(conn, findings);
		logger.info("Pushed findings to Sinas", { pushed });

		const report = await runFinalizer(conn, scanId, targetUrl, findings);
		const markdown = renderMarkdown(report);
		await fsp.writeFile(path.join(deliverablesPath, REPORT_FILENAME), markdown);

		// POST {key,value} — the PUT-by-key path 404s on this Sinas instance.
		await sinasFetch(conn, "POST", `/stores/${conn.namespace}/reports/states`, {
			key: scanId,
			value: report,
		}).catch(() => undefined);

		logger.info("Sinas finalization complete; report overwritten", { scanId });
	} catch (err) {
		logger.warn("Sinas finalization failed; keeping local report", {
			scanId,
			error: err instanceof Error ? err.message : String(err),
		});
	}
}

const ATTACK_SURFACE_FILE = "attack_surface_scenarios.json";

/** Build the attack-surface message: findings inline, no tools, severity-complete. */
function buildAttackSurfaceMessage(scanId: string, target: string, findings: FindingRecord[]): string {
	const compact = findings.map((f) => ({
		id: f.id,
		category: f.category,
		severity: f.severity,
		confidence: f.confidence,
		cwe: f.cwe,
		location: `${f.vulnerable_code_location?.file ?? ""}:${f.vulnerable_code_location?.line ?? ""}`,
		evidence: String(f.evidence ?? "").slice(0, 320),
	}));
	// No numeric cap on scenarios — a fixed cap dropped real high-impact chains.
	// Require full critical/high coverage; the v2 agent's token budget makes it fit.
	return (
		`Produce the chained attack-surface scenarios for scan ${scanId} (target ${target}).\n` +
		`Do NOT call tools — use ONLY the ${findings.length} findings below. Cover EVERY critical and high finding — each MUST appear in required_findings of at least one scenario; do not omit any. Chain related findings into the most dangerous end-to-end paths, ordered most-severe-first. Produce as many scenarios as the findings genuinely warrant (merge duplicates, do not pad).\n\n` +
		`FINDINGS JSON:\n${JSON.stringify(compact)}`
	);
}

/** Drive the attack-surface agent (Opus on Sinas) and return its `{ scenarios }` doc. */
async function runAttackSurface(
	conn: SinasConnection,
	scanId: string,
	target: string,
	findings: FindingRecord[],
): Promise<{ scenarios?: unknown[] }> {
	const chatRes = await sinasFetch(
		conn,
		"POST",
		`/agents/${conn.namespace}/${conn.attackSurfaceAgent}/chats`,
		{ title: `attack-surface ${scanId}`, input: { scan_id: scanId, target } },
	);
	if (!chatRes.ok) throw new Error(`create chat failed: ${chatRes.status}`);
	const chat = (await chatRes.json()) as { id?: string };
	if (!chat.id) throw new Error("no chat id");
	const msgRes = await sinasFetch(conn, "POST", `/chats/${chat.id}/messages/stream`, {
		content: buildAttackSurfaceMessage(scanId, target, findings),
	});
	if (!msgRes.ok) throw new Error(`attack-surface message failed: ${msgRes.status}`);
	// Reuse the finalizer SSE parser (concatenates deltas, parses assembled JSON).
	return parseFinalizerStream(await msgRes.text()) as { scenarios?: unknown[] };
}

/**
 * Offload attack-surface synthesis to the connected Sinas instance (Opus), writing
 * the result over the engine's local `attack_surface_scenarios.json` so the sink
 * posts the richer scenarios. Best-effort: any failure keeps the local file.
 */
export async function finalizeAttackSurfaceViaSinas(
	deliverablesPath: string,
	scanId: string,
	targetUrl: string,
	logger: ActivityLogger,
): Promise<void> {
	const conn = resolveSinasConnection();
	if (!conn) return;
	try {
		const findings = collectFindings(deliverablesPath, logger);
		if (findings.length === 0) return;
		const doc = await runAttackSurface(conn, scanId, targetUrl, findings);
		if (!doc || !Array.isArray(doc.scenarios)) throw new Error("no scenarios returned");
		await fsp.writeFile(path.join(deliverablesPath, ATTACK_SURFACE_FILE), `${JSON.stringify(doc, null, 2)}\n`);
		logger.info("Sinas attack-surface synthesis complete; scenarios overwritten", {
			scanId,
			scenarios: doc.scenarios.length,
		});
	} catch (err) {
		logger.warn("Sinas attack-surface synthesis failed; keeping engine output", {
			scanId,
			error: err instanceof Error ? err.message : String(err),
		});
	}
}

const IMPROVED_FINDINGS_FILE = "improved_findings.json";
const IMPROVE_BATCH = 20;

/** One improved finding (text fields only; identity stays on the original record). */
interface ImprovedFinding {
	id?: string;
	title?: string;
	evidence?: string;
	missing_defense?: string;
	remediation?: string;
	safe_poc?: string;
	repro_steps?: string[];
}

/** Build the improver message: a batch of raw findings inline, no tools. */
function buildImproveMessage(findings: FindingRecord[]): string {
	const compact = findings.map((f) => ({
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
	return (
		`Rewrite these ${compact.length} findings for clarity and correct formatting. Use ONLY this data; do not call tools. ` +
		`Return EVERY finding, keyed by its exact id, with cleaned title/evidence/missing_defense/remediation/safe_poc/repro_steps.\n\n` +
		`FINDINGS JSON:\n${JSON.stringify(compact)}`
	);
}

/** Drive the findings-improver agent over one batch; returns improved entries. */
async function runImprover(
	conn: SinasConnection,
	scanId: string,
	findings: FindingRecord[],
): Promise<ImprovedFinding[]> {
	const chatRes = await sinasFetch(conn, "POST", `/agents/${conn.namespace}/${conn.improverAgent}/chats`, {
		title: `improve ${scanId}`,
		input: { scan_id: scanId },
	});
	if (!chatRes.ok) throw new Error(`create chat failed: ${chatRes.status}`);
	const chat = (await chatRes.json()) as { id?: string };
	if (!chat.id) throw new Error("no chat id");
	const msgRes = await sinasFetch(conn, "POST", `/chats/${chat.id}/messages/stream`, {
		content: buildImproveMessage(findings),
	});
	if (!msgRes.ok) throw new Error(`improver message failed: ${msgRes.status}`);
	const doc = parseFinalizerStream(await msgRes.text()) as { findings?: ImprovedFinding[] };
	return Array.isArray(doc.findings) ? doc.findings : [];
}

/**
 * "Improvement findings" pass (ADR): before the report, a Sonnet agent rewrites
 * every finding's prose for readability + correct formatting (real fenced bash /
 * http blocks instead of crammed inline markdown). The improved text is written
 * to `improved_findings.json`; `collectFindings` overlays it, so the dashboard,
 * the report, and the attack surface all use the cleaned findings. Best-effort:
 * any failure leaves the raw findings in place. Batched to fit the token budget.
 */
export async function improveFindingsViaSinas(
	deliverablesPath: string,
	scanId: string,
	logger: ActivityLogger,
): Promise<void> {
	const conn = resolveSinasConnection();
	if (!conn) return;
	try {
		const findings = collectFindings(deliverablesPath, logger);
		if (findings.length === 0) return;
		const improved: ImprovedFinding[] = [];
		for (let i = 0; i < findings.length; i += IMPROVE_BATCH) {
			const batch = findings.slice(i, i + IMPROVE_BATCH);
			improved.push(...(await runImprover(conn, scanId, batch)));
		}
		await fsp.writeFile(
			path.join(deliverablesPath, IMPROVED_FINDINGS_FILE),
			`${JSON.stringify({ findings: improved })}\n`,
		);
		logger.info("Findings improved via Sinas", { scanId, improved: improved.length });
	} catch (err) {
		logger.warn("Findings improvement failed; keeping raw findings", {
			scanId,
			error: err instanceof Error ? err.message : String(err),
		});
	}
}
