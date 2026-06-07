// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * One screen voter: frame the shared base prompt with its lens/ordinal/session,
 * run it in structured-output mode, and reduce the result to a ballot.
 *
 * The lens and voter ordinal reach the model PURELY through `PromptContext`
 * (`applyPromptContext` fills `{{LENS}}` / `{{VOTER_INDEX}}`), so the per-category
 * `screen-*.txt` templates are never edited — the panel layers its framing on
 * top of the unmodified screen prompt.
 */

import {
	parseOr,
	runStructured,
	type ScreenVerdict,
	screenVerdictSchema,
} from "../../ai/structured/index.js";
import type { ModelTier } from "../../ai/models.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { ProviderConfig } from "../../types/config.js";
import type { PlaywrightSession } from "../../types/agents.js";
import { applyPromptContext } from "../prompt-manager/prompt-context.js";
import type { ScreenVote } from "./types.js";

/**
 * A screen is a focused pass/reject, not a full exploit — but it DOES live-probe
 * the target, so the cap must leave room to reach the right service origin and run
 * a couple of probes. The old 15 was too tight: against a target whose API sits on
 * a separate port, voters burned all 15 turns flailing at the SPA and fail-opened
 * en masse. 30 gives genuine probing headroom while still bounding runaway loops;
 * hitting the cap still fails open to "uncertain" (no recall lost). Env-overridable
 * (SHOR_SCREEN_VOTER_MAX_TURNS).
 */
const SCREEN_VOTER_MAX_TURNS =
	Number(process.env.SHOR_SCREEN_VOTER_MAX_TURNS) || 30;

/**
 * The authoritative voter framing appended AFTER the rendered screen prompt (so
 * it overrides the template's file-writing deliverable + completion trigger).
 * `{{LENS}}` / `{{VOTER_INDEX}}` are resolved via `applyPromptContext`; the
 * candidate id and session are mechanical substitutions.
 */
export function voterFramingBlock(args: {
	lens: string;
	voter: number;
	candidateId: string;
	session: string;
}): string {
	const { lens, voter, candidateId, session } = args;
	const template = [
		"",
		"<screen_voter_panel>",
		"You are screen voter #{{VOTER_INDEX}} on an INDEPENDENT panel of skeptics.",
		"This block OVERRIDES the <deliverable_instructions> and <conclusion_trigger>",
		"above: do NOT write any *_screened_queue.json or *_screen_rejected.json file,",
		"and do NOT announce a completion phrase. Your ONLY output is one structured",
		"verdict object.",
		"",
		`Judge EXACTLY ONE candidate — the queue entry whose ID is \`${candidateId}\`.`,
		"Ignore every other entry. Weigh it primarily through your assigned lens:",
		'  Lens "{{LENS}}":',
		"    - reachability      does the reported source actually reach the sink, and is",
		"                        the endpoint reachable at all? An unreachable claim is refuted.",
		"    - control-sanitizer is a context-correct, un-bypassed defense in place at the slot?",
		"    - exploitability    does a benign, minimal probe reproduce the vulnerable behavior?",
		"    - auth-context      does the claim still hold under the real identity/role boundary?",
		"  Apply YOUR lens; the others are listed only for shared vocabulary.",
		"",
		`For any browser automation use Playwright session \`-s=${session}\` — this`,
		"voter's isolated session, overriding any session named earlier in the prompt.",
		"",
		"TARGET THE RIGHT ORIGIN. Probe against the service origin from the AUTHORITATIVE",
		"reachable-surface list in the <target> block above (an API typically lives on a",
		"distinct port, e.g. the :8080 origin) — NOT the primary SPA origin. If a path on",
		"the primary origin returns the SPA shell / index.html / a static 404-405, you are",
		"on the wrong origin; switch to the API origin from that list and retry there.",
		"FAIL FAST — do NOT burn your turn budget: if, AFTER probing the CORRECT service",
		"origin, the endpoint is genuinely non-responsive, conclude immediately — emit",
		'verdict "uncertain" with `reason` starting "unreachable:" plus the origin you',
		"tried. Never spend the whole budget flailing at the SPA.",
		"",
		"Emit the structured object { id, verdict, lens, reason }:",
		`  - id      = \`${candidateId}\` verbatim.`,
		'  - verdict = "refute" when you hold affirmative evidence it is NOT exploitable;',
		'              "support" when you reproduced vulnerable behavior OR could not refute',
		"                        it (benefit of the doubt — never drop what you cannot test);",
		'              "uncertain" only when genuinely undecided after a fair attempt.',
		'  - lens    = "{{LENS}}".',
		"  - reason  = one concrete sentence grounded in your own probing.",
		"</screen_voter_panel>",
		"",
	].join("\n");
	return applyPromptContext(template, { lens, voterIndex: voter });
}

/** Inputs for {@link runVoter}. `basePrompt` is the rendered screen template, shared across a panel's voters. */
export interface VoterRunArgs {
	basePrompt: string;
	candidateId: string;
	lens: string;
	voter: number;
	/** The isolated Playwright session this voter drives, leased from the pool. */
	session: PlaywrightSession;
	/** Agent cwd (the repo path) — the voter's `sourceDir`. */
	sourceDir: string;
	/** Relative deliverables subdir, forwarded to the SDK env. */
	deliverablesSubdir: string;
	modelTier: ModelTier;
	/** Log/timer + skill-attribution label, e.g. `injection-screen`. */
	agentLabel: string;
	providerConfig?: ProviderConfig;
	logger: ActivityLogger;
}

/**
 * Run one voter and reduce it to a ballot. Never throws: a missing/garbled
 * structured output fails OPEN to an `uncertain` ballot (a dead voter must never
 * be the reason a finding is dropped). The assigned `lens` — not the model's
 * echoed `lens` — is recorded, so the panel's diversity is ground truth.
 */
export async function runVoter(args: VoterRunArgs): Promise<ScreenVote> {
	const {
		basePrompt,
		candidateId,
		lens,
		voter,
		session,
		sourceDir,
		deliverablesSubdir,
		modelTier,
		agentLabel,
		providerConfig,
		logger,
	} = args;

	const prompt = `${basePrompt}\n${voterFramingBlock({ lens, voter, candidateId, session })}`;

	const result = await runStructured<ScreenVerdict>({
		prompt,
		sourceDir,
		schema: screenVerdictSchema,
		modelTier,
		agentName: `${agentLabel}-v${voter}`,
		logger,
		deliverablesSubdir,
		maxTurns: SCREEN_VOTER_MAX_TURNS,
		...(providerConfig !== undefined ? { providerConfig } : {}),
	});

	const fallback: ScreenVerdict = {
		id: candidateId,
		verdict: "uncertain",
		lens,
		reason: "voter produced no structured verdict (fail-open)",
	};
	const verdict = parseOr(result, fallback);

	return {
		voter,
		lens,
		verdict: verdict.verdict,
		reason: typeof verdict.reason === "string" ? verdict.reason : "",
	};
}
