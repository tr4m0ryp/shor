// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Built-in default taint specs + deterministic language detection.
 *
 * These are the DETERMINISTIC backbone: even with no LLM auth the driver runs
 * with a curated, framework-agnostic source/sink/sanitizer catalogue and a
 * generic DB write->read through-step, so second-order detection works out of
 * the box. `specs/infer.ts` layers LLM refinements ON TOP of these (never
 * replacing them), because an LLM alone is an unsound taint tracker (T10).
 *
 * Matchers are Joern name regexes matched against a call's `.name`. They are
 * intentionally broad (recall over precision) — the CPG reachability + the proof
 * oracle downstream are what buy precision. JS/TS matches stay lower-confidence.
 */

import type {
	SinkSpec,
	TaintConfidence,
	TaintLanguage,
	TaintSpec,
	ThroughStepSpec,
} from "../types.js";

/** File extensions -> CPG language, used for the dominant-language vote. */
const EXT_LANGUAGE: Record<string, TaintLanguage> = {
	".ts": "typescript",
	".tsx": "typescript",
	".mts": "typescript",
	".cts": "typescript",
	".js": "javascript",
	".jsx": "javascript",
	".mjs": "javascript",
	".cjs": "javascript",
	".java": "java",
	".py": "python",
	".go": "go",
	".c": "c",
	".h": "c",
};

/** Map one file path to a language, or undefined if not a known source ext. */
export function languageForPath(file: string): TaintLanguage | undefined {
	const dot = file.lastIndexOf(".");
	if (dot < 0) return undefined;
	return EXT_LANGUAGE[file.slice(dot).toLowerCase()];
}

/**
 * Pick the dominant language from a list of file paths (a simple max-count
 * vote). TS wins ties over JS because a `.ts`+`.js` repo is a TS project with
 * emitted output. Returns "unknown" when nothing matches.
 */
export function detectLanguageFromFiles(files: readonly string[]): TaintLanguage {
	const counts = new Map<TaintLanguage, number>();
	for (const f of files) {
		const lang = languageForPath(f);
		if (lang) counts.set(lang, (counts.get(lang) ?? 0) + 1);
	}
	if (counts.size === 0) return "unknown";
	let best: TaintLanguage = "unknown";
	let bestN = -1;
	for (const [lang, n] of counts) {
		// TS outranks JS on an equal count (transpiled-output tie-break).
		if (n > bestN || (n === bestN && lang === "typescript")) {
			best = lang;
			bestN = n;
		}
	}
	return best;
}

/** JS/TS frontends (jssrc2cpg) are weaker -> every flow they yield is tentative. */
export function confidenceForLanguage(lang: TaintLanguage): TaintConfidence {
	return lang === "javascript" || lang === "typescript" ? "tentative" : "firm";
}

// --- Framework-agnostic catalogues (broad name matchers) ---------------------

// Joern matches `.code(pat)` as a FULL-STRING regex, so JS field-access chains
// like `req.body.bio` need surrounding wildcards to match (validated on a real
// TS target — without them the write-side/second-order flows are silently
// missed). Java-style named accessors (`getParameter`) match by call name.
const BASE_SOURCES: readonly string[] = [
	"(?i).*getParameter.*",
	"(?i).*getHeader.*",
	"(?i).*getQueryString.*",
	"(?i).*get(Query|Body|Params|Cookies?|Input).*",
	"(?i).*readLine.*",
	"(?i).*(req|request|ctx|event)\\.(query|body|params|headers|cookies|form|files).*",
];

const BASE_SANITIZERS: readonly string[] = [
	"(?i).*escape.*",
	"(?i).*sanitize.*",
	"(?i).*encode.*",
	"(?i).*escapeHtml.*",
	"(?i).*parameterize.*",
	"(?i).*validate.*",
	"(?i)quote.*",
	"(?i)parseInt",
	"(?i)Number",
];

const BASE_SINKS: readonly SinkSpec[] = [
	{ name: "(?i).*(query|execute|exec|rawQuery|prepareStatement).*", vulnClass: "sql_injection", cwe: "CWE-89" },
	{ name: "(?i).*(exec|execSync|spawn|system|popen|Runtime.exec).*", vulnClass: "command_injection", cwe: "CWE-78" },
	{ name: "(?i).*(innerHTML|render|writeHead|send|write|html|dangerouslySetInnerHTML).*", vulnClass: "xss", cwe: "CWE-79" },
	{ name: "(?i).*(readFile|readFileSync|createReadStream|sendFile|openSync|fopen).*", vulnClass: "path_traversal", cwe: "CWE-22" },
	{ name: "(?i).*(fetch|axios|urlopen|getForObject|httpGet|request).*", vulnClass: "ssrf", cwe: "CWE-918" },
	{ name: "(?i)(eval|Function|deserialize|unserialize|pickle.loads|yaml.load).*", vulnClass: "code_injection", cwe: "CWE-94" },
];

/** Generic DB/cache persistence pair — the second-order through-step backbone. */
const BASE_THROUGH_STEPS: readonly ThroughStepSpec[] = [
	{
		store: "db",
		// DB-oriented verbs only. Generic English tokens (get/all/first/query)
		// are deliberately EXCLUDED: they collide with request-input sources and
		// inflate spurious second-order pairs. The LLM spec inference names the
		// repo's CONCRETE data-layer methods to tighten this per target.
		writeMethods: [
			"(?i).*(insert|create|save|update|upsert|persist|store|write).*",
		],
		readMethods: [
			"(?i).*(findOne|findAll|findBy|find|select|load|fetch|scan|readRow).*",
		],
	},
];

/**
 * The built-in default spec for a language. `inferredBy: "default"` marks it as
 * the deterministic backbone; `inferSpec` clones and augments it when the LLM
 * runs. Per-language overrides are minimal today — the base catalogue is broad
 * enough that the LLM's refinements carry the language-specific precision.
 */
export function defaultSpec(language: TaintLanguage): TaintSpec {
	return {
		language,
		sources: [...BASE_SOURCES],
		sinks: [...BASE_SINKS],
		sanitizers: [...BASE_SANITIZERS],
		throughSteps: [...BASE_THROUGH_STEPS],
		inferredBy: "default",
	};
}
