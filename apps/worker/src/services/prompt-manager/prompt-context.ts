// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Per-round context resolved into the newer `{{...}}` prompt placeholders.
 *
 * Every field is OPTIONAL. When a field is absent, `applyPromptContext`
 * substitutes a neutral sentinel ("(none)") so a rendered prompt NEVER carries a
 * literal `{{VAR}}` forward. Each field is owned by a later build task (noted on
 * the field) that renders its value out-of-band and threads it through
 * `loadPrompt`; until that task lands, the sentinel keeps prompts rendering
 * sensibly. Values are pre-rendered strings — interpolation only substitutes,
 * it never formats.
 */
export interface PromptContext {
	/** `{{THREAT_MODEL}}` — rendered threat-model summary (task 005). */
	threatModel?: string;
	/** `{{HISTORICAL_SEED}}` — prior-exploit hot-spots (task 006). */
	historicalSeed?: string;
	/** `{{PARTITION}}` — attack-surface slice assigned this round (task 007). */
	partition?: string;
	/** `{{LENS}}` — discovery/verification lens label (task 007/011). */
	lens?: string;
	/** `{{VOTER_INDEX}}` — screen voter ordinal (task 011). */
	voterIndex?: number;
	/**
	 * `{{IDENTITIES}}` — identity labels + roles, METADATA ONLY (task 008).
	 * NEVER credentials: same rule as auth-context.ts / ADR-050. The renderer
	 * that fills this must emit labels/roles only, never secret material.
	 */
	identities?: string;
	/** `{{FP_RULES}}` — org false-positive precedents (task 016). */
	fpRules?: string;
	/**
	 * `{{TARGET_POSTURE}}` — EXPLOIT/screen impact posture (task 003).
	 * assembleScanPromptContext selects the minimal-impact block by DEFAULT and
	 * the disposable-target block only on operator opt-in (SHOR_EXPENDABLE_TARGET).
	 * Destructive exploitation is never the default; an unset value renders the
	 * neutral "(none)" sentinel, which is SAFE (it authorizes nothing destructive).
	 */
	targetPosture?: string;
}

/**
 * Substitute every `PromptContext`-backed `{{VAR}}` in `template`. Absent values
 * collapse to the neutral sentinel so no literal placeholder survives. An
 * explicit empty string is honoured (it is not nullish) — a caller can blank a
 * section deliberately. Substitution-only, mirroring `interpolateVariables`.
 */
export function applyPromptContext(
	template: string,
	context: PromptContext = {},
): string {
	const NONE = "(none)";
	return template
		.replace(/{{THREAT_MODEL}}/g, context.threatModel ?? NONE)
		.replace(/{{HISTORICAL_SEED}}/g, context.historicalSeed ?? NONE)
		.replace(/{{PARTITION}}/g, context.partition ?? NONE)
		.replace(/{{LENS}}/g, context.lens ?? NONE)
		.replace(
			/{{VOTER_INDEX}}/g,
			context.voterIndex !== undefined ? String(context.voterIndex) : NONE,
		)
		.replace(/{{IDENTITIES}}/g, context.identities ?? NONE)
		.replace(/{{FP_RULES}}/g, context.fpRules ?? NONE)
		.replace(/{{TARGET_POSTURE}}/g, context.targetPosture ?? NONE);
}
