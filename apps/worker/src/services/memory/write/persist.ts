// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Dual-embedding write path for the learning memory (task 011, spec T3/R3/§6.6).
 *
 * The "remember" half of the loop, running at/after the findings sink write
 * choke point (`apps/web/src/findings/sink.ts` `ingestFindings`). Per finding:
 *   1. verbalize (schema/) -> labeled doc (Vector A) + code block (Vector B),
 *   2. MANDATORY scrub (task 003) of the doc + code + FP reason — fail-closed:
 *      a scrub failure aborts the write, no unscrubbed text ever reaches embed,
 *   3. embed code + text (task 002 client),
 *   4. upsert `finding_embedding` (local tier) and, for a refuted finding,
 *      `fp_memory` (next-scan auto-filter — task 013 consumes it).
 *
 * Cross-package boundary: the pgvector repositories live in `apps/web`; the
 * worker package does not depend on `pg`/`@shor/web`. So the two writers are
 * injected PORTS that the real `findingEmbeddingRepo`/`fpMemoryRepo` satisfy
 * structurally — the eventual sink integration wires them, tests pass fakes.
 *
 * Flag-gated / default-OFF: writes only when `SHOR_MEMORY_WRITE` is enabled AND
 * an embed server is configured (`SHOR_EMBED_URL`). A stock scan is unchanged.
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";
import type { EmbedClient } from "../embed/index.js";
import type { FindingLike } from "../schema/index.js";
import { verbalize } from "../schema/index.js";
import { type ScrubDeps, scrub } from "../scrub/index.js";

/** A dense embedding — the vanilla-`pg` repos expect a 1024-dim number array. */
type Vector = readonly number[];

/**
 * Injected port for the local-tier `finding_embedding` writer. The real
 * `findingEmbeddingRepo.create` (apps/web) satisfies this structurally.
 */
export interface FindingEmbeddingWriter {
	create(input: {
		tenantId: string;
		projectId: string;
		scanId?: string | null;
		vecCode?: Vector | null;
		vecText?: Vector | null;
		cwe?: string | null;
		vulnClass?: string | null;
		severity?: string | null;
		route?: string | null;
		source?: string | null;
		sink?: string | null;
		componentVer?: string | null;
		confidence?: string | null;
	}): Promise<{ id: string }>;
}

/**
 * Injected port for the `fp_memory` writer. The real `fpMemoryRepo.upsert`
 * (apps/web) satisfies this structurally.
 */
export interface FpMemoryWriter {
	upsert(input: {
		tenantId: string;
		projectId: string;
		fingerprint: string;
		reason?: string | null;
		vecText?: Vector | null;
		decision?: string | null;
	}): Promise<{ id: string }>;
}

/** Tenant/project/scan scope for a memory write (RLS claim source). */
export interface MemoryWriteContext {
	readonly tenantId: string;
	readonly projectId: string;
	readonly scanId?: string | null;
}

/** Injected collaborators for {@link persistFinding}. */
export interface PersistDeps {
	readonly embed: EmbedClient;
	readonly scrubDeps: ScrubDeps;
	readonly embeddings: FindingEmbeddingWriter;
	readonly fpMemory: FpMemoryWriter;
	readonly logger?: ActivityLogger | undefined;
	/**
	 * Override the `SHOR_MEMORY_WRITE` env gate (mainly for tests). When unset,
	 * the env flag decides.
	 */
	readonly enabled?: boolean | undefined;
}

/** Outcome of a single-finding persist. */
export type PersistOutcome =
	| {
			readonly written: true;
			readonly embeddingId: string;
			readonly fpMemoryId?: string;
			readonly quarantinedSecrets: number;
			readonly piiRedactions: number;
	  }
	| {
			readonly written: false;
			readonly reason: "disabled" | "scrub_failed" | "error";
	  };

const MAX_FP_REASON = 500;

/** True when `SHOR_MEMORY_WRITE` is truthy (`1`/`true`, case-insensitive). */
export function readMemoryWriteEnabled(
	env: NodeJS.ProcessEnv = process.env,
): boolean {
	const raw = env["SHOR_MEMORY_WRITE"]?.trim().toLowerCase();
	return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

/** First non-empty trimmed string among candidate keys, else null. */
function firstString(
	finding: FindingLike,
	keys: readonly string[],
): string | null {
	for (const key of keys) {
		const value = finding[key];
		if (typeof value === "string" && value.trim() !== "") return value.trim();
	}
	return null;
}

/**
 * Classify how a finding was refuted for `fp_memory`, or null when it is not a
 * false positive. Conservative by design (bias to precision — never auto-filter
 * a finding that might be a real, merely out-of-scope bug): only clear
 * refutations land in memory.
 */
export function refutationDecision(finding: FindingLike): string | null {
	const disposition =
		typeof finding.disposition === "string" ? finding.disposition : "";
	if (
		disposition === "refuted_on_review" ||
		disposition === "exploited_privileged"
	)
		return "refuted";
	if (
		disposition === "unverified_screen_rejected" ||
		disposition === "out_of_scope_target"
	)
		return "false_positive";
	if (finding.premise_valid === false) return "refuted";
	if (finding.in_scope === false) return "false_positive";
	return null;
}

/** A short, human-readable refutation reason for `fp_memory`. */
function refutationReason(finding: FindingLike): string | null {
	const reason = firstString(finding, [
		"validation_note",
		"refutation_reason",
		"evidence",
	]);
	return reason ? reason.slice(0, MAX_FP_REASON) : null;
}

/**
 * Verbalize -> scrub -> embed -> upsert one finding into the local memory tier.
 * No-op (returns `{ written: false, reason: "disabled" }`) unless the memory
 * write flag is on and an embed server is configured. Scrub is mandatory and
 * fail-closed: if it cannot run, nothing is embedded or stored.
 */
export async function persistFinding(
	finding: FindingLike,
	ctx: MemoryWriteContext,
	deps: PersistDeps,
): Promise<PersistOutcome> {
	const enabled = deps.enabled ?? readMemoryWriteEnabled();
	if (!enabled || !deps.embed.enabled)
		return { written: false, reason: "disabled" };

	const v = verbalize(finding);
	const fpDecision = refutationDecision(finding);
	const fpReason = fpDecision ? refutationReason(finding) : null;
	const fingerprint = firstString(finding, ["fingerprint"]);

	// Step 2 — MANDATORY scrub of every text that will be embedded or stored.
	// Bundle doc text, code, and the FP reason into one scrub pass; fail-closed.
	const bundle: Record<string, string> = { text: v.text };
	if (v.codeBlock) bundle.code = v.codeBlock;
	if (fpReason) bundle.reason = fpReason;
	const scrubbed = await scrub(bundle, deps.scrubDeps);
	if (!scrubbed.ok) {
		deps.logger?.error(
			"memory-write: scrub failed closed — finding NOT stored",
			{
				reason: scrubbed.reason,
			},
		);
		return { written: false, reason: "scrub_failed" };
	}
	const cleanText = scrubbed.clean.text ?? "";
	const cleanCode =
		typeof scrubbed.clean.code === "string" ? scrubbed.clean.code : null;
	const cleanReason =
		typeof scrubbed.clean.reason === "string" ? scrubbed.clean.reason : null;
	const quarantinedSecrets = scrubbed.quarantined.length;
	const piiRedactions = scrubbed.pii.reduce((sum, p) => sum + p.count, 0);

	try {
		// Step 3 — embed the scrubbed text (Vector A) and code (Vector B).
		const textRes = await deps.embed.embedText([cleanText]);
		const vecText = textRes.embeddings[0] ?? null;
		let vecCode: Vector | null = null;
		if (cleanCode) {
			const codeRes = await deps.embed.embedCode([cleanCode]);
			vecCode = codeRes.embeddings[0] ?? null;
		}

		// Step 4a — upsert the local-tier embedding row (structured cols + vectors).
		const row = await deps.embeddings.create({
			tenantId: ctx.tenantId,
			projectId: ctx.projectId,
			scanId: ctx.scanId ?? null,
			vecCode,
			vecText,
			cwe: v.metadata.cwe,
			vulnClass: v.metadata.vulnClass,
			severity: v.metadata.severity,
			route: v.metadata.route,
			source: v.metadata.source,
			sink: v.metadata.sink,
			componentVer: v.metadata.componentVer,
			confidence: v.metadata.confidence,
		});

		// Step 4b — a refuted finding is also remembered for next-scan auto-filter.
		let fpMemoryId: string | undefined;
		if (fpDecision && fingerprint) {
			const fp = await deps.fpMemory.upsert({
				tenantId: ctx.tenantId,
				projectId: ctx.projectId,
				fingerprint,
				reason: cleanReason,
				vecText,
				decision: fpDecision,
			});
			fpMemoryId = fp.id;
		} else if (fpDecision && !fingerprint) {
			deps.logger?.warn(
				"memory-write: refuted finding lacks a fingerprint — skipping fp_memory",
				{},
			);
		}

		deps.logger?.info("memory-write: finding stored", {
			embeddingId: row.id,
			hasCodeVector: vecCode !== null,
			fpMemory: fpMemoryId !== undefined,
			quarantinedSecrets,
			piiRedactions,
		});
		return {
			written: true,
			embeddingId: row.id,
			...(fpMemoryId !== undefined && { fpMemoryId }),
			quarantinedSecrets,
			piiRedactions,
		};
	} catch (err) {
		const reason = err instanceof Error ? err.message : String(err);
		deps.logger?.error(
			"memory-write: embed/store failed — finding NOT stored",
			{ reason },
		);
		return { written: false, reason: "error" };
	}
}

/**
 * Persist a batch of findings, one at a time (each embed/store is independent
 * so a single failure never discards the rest). Returns per-finding outcomes in
 * input order.
 */
export async function persistFindings(
	findings: readonly FindingLike[],
	ctx: MemoryWriteContext,
	deps: PersistDeps,
): Promise<PersistOutcome[]> {
	const outcomes: PersistOutcome[] = [];
	for (const finding of findings) {
		outcomes.push(await persistFinding(finding, ctx, deps));
	}
	return outcomes;
}
