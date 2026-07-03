// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Distill a public technique write-up into a seed exemplar (`novel` tier).
 *
 * An LLM structured call extracts the {@link SeedExemplar} fields from raw
 * write-up text. The runner is an INJECTED PORT (`runStructured`, task
 * ai/structured) so tests mock it and no network is touched.
 *
 * LICENSING INVARIANT (F-licensing): we persist ONLY the distilled, structured
 * fields plus a provenance URL — NEVER verbatim source text. The raw text is a
 * transient LLM input; it is not stored, embedded, or returned. The extraction
 * prompt instructs the model to PARAPHRASE into abstract mechanism descriptions,
 * not to copy sentences.
 */

import type { JsonSchemaOutputFormat } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";
import type { ModelTier } from "../../../../ai/models.js";
import type {
	RunStructuredArgs,
	StructuredResult,
} from "../../../../ai/structured/index.js";
import type { ActivityLogger } from "../../../../types/activity-logger.js";
import type { SeedExemplar, SeedProvenance } from "../types.js";

/** Cap on write-up text sent to the model (keeps the prompt bounded). */
const MAX_RAW_CHARS = 20_000;

/**
 * Injected LLM port — structurally satisfied by task ai/structured's
 * `runStructured`. Generic so the caller keeps full typing; tests pass a fake.
 */
export type StructuredRunner = <T>(
	args: RunStructuredArgs<T>,
) => Promise<StructuredResult<T>>;

/** Zod schema for the fields the distiller extracts (single source of truth). */
const DistilledDef = z.object({
	technique: z.string().min(1),
	aliases: z.array(z.string()).optional(),
	preconditions: z.string().min(1),
	rootCause: z.string().min(1),
	source: z.string().min(1),
	sink: z.string().min(1),
	probeSignal: z.string().min(1),
	pocSkeleton: z.string(),
	cwe: z.string().optional(),
	capecId: z.string().optional(),
	tags: z.array(z.string()),
});
type Distilled = z.infer<typeof DistilledDef>;

/** The SDK's AJV validator expects draft-07 (Zod defaults to draft-2020-12). */
const DISTILL_SCHEMA: JsonSchemaOutputFormat = {
	type: "json_schema",
	schema: z.toJSONSchema(DistilledDef, { target: "draft-07" }) as Record<
		string,
		unknown
	>,
};

/** Injected collaborators for {@link distillWriteup}. */
export interface DistillDeps {
	readonly runStructured: StructuredRunner;
	/** Public provenance (origin + canonical URL) attached to the result. */
	readonly provenance: SeedProvenance;
	/** Working dir the structured agent runs in; defaults to `process.cwd()`. */
	readonly sourceDir?: string;
	readonly modelTier?: ModelTier;
	readonly logger?: ActivityLogger;
}

const EXTRACTION_INSTRUCTIONS = [
	"You are distilling a PUBLIC web-security technique write-up into a compact,",
	"reusable exemplar for a retrieval index. Extract ONLY the abstract mechanism.",
	"",
	"Rules:",
	"- PARAPHRASE in your own words; never copy sentences from the source.",
	"- `technique`: a short canonical name for the technique class.",
	"- `preconditions`: what must hold for the technique to apply.",
	"- `rootCause`: the underlying weakness it exploits.",
	"- `source`/`sink`: the abstract data flow (attacker input -> dangerous op).",
	"- `probeSignal`: the observable that confirms the technique is present.",
	"- `pocSkeleton`: a MINIMAL, GENERIC proof-of-concept sketch (no target names,",
	"  no verbatim payloads from the source); empty string if none is warranted.",
	"- `cwe`/`capecId`: identifiers when clearly implied (e.g. 'CWE-918').",
	"- `tags`: a few lowercase keywords.",
].join("\n");

/** Build the extraction prompt (raw text is transient input, never stored). */
function buildPrompt(rawText: string): string {
	const clipped = rawText.slice(0, MAX_RAW_CHARS);
	return `${EXTRACTION_INSTRUCTIONS}\n\n--- WRITE-UP (source; do not quote) ---\n${clipped}\n--- END WRITE-UP ---`;
}

/** Assemble a `novel`-tier exemplar from the distilled fields + provenance. */
function toExemplar(d: Distilled, provenance: SeedProvenance): SeedExemplar {
	const aliases = (d.aliases ?? []).map((a) => a.trim()).filter(Boolean);
	return {
		technique: d.technique.trim(),
		...(aliases.length > 0 ? { aliases } : {}),
		preconditions: d.preconditions.trim(),
		rootCause: d.rootCause.trim(),
		source: d.source.trim(),
		sink: d.sink.trim(),
		probeSignal: d.probeSignal.trim(),
		pocSkeleton: d.pocSkeleton.trim(),
		...(d.cwe?.trim() ? { cwe: d.cwe.trim() } : {}),
		...(d.capecId?.trim() ? { capecId: d.capecId.trim() } : {}),
		tags: d.tags.map((t) => t.trim().toLowerCase()).filter(Boolean),
		noveltyTier: "novel",
		provenance,
	};
}

/**
 * Distill a raw write-up into a `novel`-tier {@link SeedExemplar}, or `null` when
 * the text is empty or the structured call yields nothing usable. Never throws:
 * `runStructured` is contractually non-throwing, and a failed extraction is a
 * clean `null` (the caller simply seeds one fewer exemplar).
 */
export async function distillWriteup(
	rawText: string,
	deps: DistillDeps,
): Promise<SeedExemplar | null> {
	const text = rawText?.trim();
	if (!text) return null;

	const result = await deps.runStructured<Distilled>({
		prompt: buildPrompt(text),
		sourceDir: deps.sourceDir ?? process.cwd(),
		schema: DISTILL_SCHEMA,
		modelTier: deps.modelTier ?? "medium",
		agentName: "seed-distiller",
		validator: DistilledDef,
	});

	if (!result.ok) {
		deps.logger?.warn("seed-distill: extraction failed — skipping write-up", {
			error: result.error,
			url: deps.provenance.url ?? null,
		});
		return null;
	}

	const parsed = DistilledDef.safeParse(result.value);
	if (!parsed.success) {
		deps.logger?.warn("seed-distill: distilled fields failed validation", {
			url: deps.provenance.url ?? null,
		});
		return null;
	}
	return toExemplar(parsed.data, deps.provenance);
}
