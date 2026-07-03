// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * The semantic half of guard-dominance (spec T10, F9b): structural dominance
 * proves "a check runs"; this proves WHAT it asserts.
 *
 * A guard can dominate a sink on every path yet still authorize the wrong thing —
 * `isLoggedIn` dominating a "delete ANY user's post" sink is a textbook broken
 * object-level authorization even though a check demonstrably runs. So for a
 * structurally-guarded sink we ask the LLM (its ONLY job — it never tracks flow)
 * whether the dominating guard actually authorizes THIS resource + verb.
 *
 * Fail-open + flag-gated: the classifier is pure and total; when the semantic
 * layer is disabled a guarded sink is `adequate` (no finding manufactured), and a
 * consulted-but-undecidable case is held as `unproven`, never silently cleared.
 */

import type { JsonSchemaOutputFormat } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";
import { runStructured } from "../../../ai/structured/index.js";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import type {
	GuardCandidate,
	GuardDisposition,
	GuardFinding,
	GuardSemanticVerdict,
} from "./types.js";

/** Structured verdict the LLM returns per guarded sink (or undefined on failure). */
export type GuardSemanticAsk = (
	candidate: GuardCandidate,
) => Promise<GuardSemanticVerdict | undefined>;

const VerdictDef = z.object({
	assertsAuthorization: z.boolean(),
	resourceScoped: z.boolean(),
	verbScoped: z.boolean(),
	rationale: z.string(),
});
type VerdictOut = z.infer<typeof VerdictDef>;

/** Local Zod->draft-07 converter (the SDK's AJV wants draft-07, not 2020-12). */
function toOutputFormat(schema: z.ZodType): JsonSchemaOutputFormat {
	return {
		type: "json_schema",
		schema: z.toJSONSchema(schema, { target: "draft-07" }) as Record<string, unknown>,
	};
}
const verdictSchema = toOutputFormat(VerdictDef);

/** LLM semantic validation is opt-in and needs CLI/API auth to run. */
export function guardSemanticEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
	if (env.SHOR_GUARD_DOMINANCE_LLM === "0") return false;
	return !!(env.CLAUDE_CODE_OAUTH_TOKEN || env.ANTHROPIC_API_KEY);
}

/**
 * Pure disposition rule. `consulted` records whether the semantic layer even ran
 * for this candidate (it only runs for structurally-guarded sinks), which lets a
 * guarded sink fail OPEN to `adequate` when the layer is off but be held as
 * `unproven` when the model was asked and could not decide.
 */
export function classifyGuard(
	candidate: GuardCandidate,
	opts: { semantic?: GuardSemanticVerdict | undefined; consulted: boolean },
): GuardDisposition {
	if (candidate.structuralVerdict !== "guarded") return "missing_guard";
	if (!opts.consulted) return "adequate"; // fail-open: a dominating check exists
	if (!opts.semantic) return "unproven"; // asked, no verdict -> held, not cleared
	const s = opts.semantic;
	if (!s.assertsAuthorization || !s.resourceScoped || !s.verbScoped) return "wrong_guard";
	return "adequate";
}

function buildPrompt(candidate: GuardCandidate): string {
	const guardCode = candidate.dominatingGuards
		.map((g) => `- ${g.code ?? g.method ?? "guard"} (${g.file ?? "?"}:${g.line ?? "?"})`)
		.join("\n");
	return [
		"You are auditing an authorization guard that a control-flow dominator analysis PROVED runs on every path to a sensitive operation.",
		"Decide WHAT the guard asserts — do not re-derive whether it runs (that is already proven).",
		`Sensitive operation (sink): ${candidate.sink.code ?? candidate.sink.method ?? "?"} at ${candidate.sink.file ?? "?"}:${candidate.sink.line ?? "?"}`,
		`In method: ${candidate.method ?? "?"}`,
		"Dominating guard call(s):",
		guardCode || "- (none captured; inspect the method)",
		"Inspect the repository in your working directory. Return JSON:",
		"- assertsAuthorization: does the guard make an authorization decision (not merely presence/logging)?",
		"- resourceScoped: is the check bound to the SPECIFIC resource this operation touches (e.g. ownership of the row), not just any-authenticated?",
		"- verbScoped: does the authorized action/verb match this operation (read vs write vs delete vs admin)?",
		"- rationale: one sentence, no code snippets, no secrets.",
	].join("\n");
}

/** Build the real LLM-backed ask for a repo. Returns undefined on any failure. */
export function createGuardSemanticAsk(sourceDir: string, logger?: ActivityLogger): GuardSemanticAsk {
	return async (candidate) => {
		const result = await runStructured<VerdictOut>({
			prompt: buildPrompt(candidate),
			sourceDir,
			schema: verdictSchema,
			agentName: "guard-dominance-semantic",
			...(logger ? { logger } : {}),
		});
		if (!result.ok) return undefined;
		return result.value;
	};
}

/** Options for {@link validateGuards}. */
export interface ValidateGuardsOptions {
	/** Injectable semantic ask (tests pass a fake; production builds the LLM one). */
	ask?: GuardSemanticAsk;
	/** Repo dir for the default LLM ask (ignored when `ask` is provided). */
	sourceDir?: string;
	logger?: ActivityLogger;
	/** Force-enable/disable the semantic layer (defaults to {@link guardSemanticEnabled}). */
	enabled?: boolean;
}

/**
 * Fold structural candidates with the semantic layer into final {@link GuardFinding}s.
 * The LLM is consulted ONLY for structurally-`guarded` sinks (the "is it the RIGHT
 * guard" question); unguarded/partial sinks are `missing_guard` from structure
 * alone. Never throws: an ask that rejects yields an undecided (`unproven`) verdict.
 */
export async function validateGuards(
	candidates: readonly GuardCandidate[],
	opts: ValidateGuardsOptions = {},
): Promise<GuardFinding[]> {
	const enabled = opts.enabled ?? guardSemanticEnabled();
	const ask =
		opts.ask ?? (enabled && opts.sourceDir ? createGuardSemanticAsk(opts.sourceDir, opts.logger) : undefined);

	const out: GuardFinding[] = [];
	for (const candidate of candidates) {
		if (candidate.structuralVerdict !== "guarded") {
			out.push({ ...candidate, disposition: classifyGuard(candidate, { consulted: false }) });
			continue;
		}
		const consulted = !!ask;
		let semantic: GuardSemanticVerdict | undefined;
		if (ask) {
			try {
				semantic = await ask(candidate);
			} catch {
				semantic = undefined; // fail-open: undecidable, not cleared
			}
		}
		out.push({
			...candidate,
			semantic,
			disposition: classifyGuard(candidate, { semantic, consulted }),
		});
	}
	return out;
}
