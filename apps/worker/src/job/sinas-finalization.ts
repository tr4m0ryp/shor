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
	const finalizerAgent = process.env.SINAS_FINALIZER_AGENT ?? "finalizer";
	if (!enabled || !url || !apiKey) return null;
	return { url: url.replace(/\/+$/, ""), apiKey, namespace, finalizerAgent };
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

/** Drive the finalizer agent over the chat stream and return its structured report. */
async function runFinalizer(
	conn: SinasConnection,
	scanId: string,
	target: string,
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
		{ content: `Produce the finalized report for scan ${scanId}.` },
	);
	if (!msgRes.ok) throw new Error(`finalizer message failed: ${msgRes.status}`);

	return parseFinalizerStream(await msgRes.text());
}

/** Parse the SSE stream: surface provider errors, return the last JSON message. */
function parseFinalizerStream(stream: string): SinasReport {
	let last: SinasReport | null = null;
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
		if (typeof content === "object" && content !== null) {
			last = content as SinasReport;
		} else if (typeof content === "string") {
			try {
				last = JSON.parse(content) as SinasReport;
			} catch {
				/* not JSON yet */
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

		const report = await runFinalizer(conn, scanId, targetUrl);
		const markdown = renderMarkdown(report);
		await fsp.writeFile(path.join(deliverablesPath, REPORT_FILENAME), markdown);

		await sinasFetch(
			conn,
			"PUT",
			`/stores/${conn.namespace}/reports/states/${scanId}`,
			{ value: report },
		).catch(() => undefined);

		logger.info("Sinas finalization complete; report overwritten", { scanId });
	} catch (err) {
		logger.warn("Sinas finalization failed; keeping local report", {
			scanId,
			error: err instanceof Error ? err.message : String(err),
		});
	}
}
