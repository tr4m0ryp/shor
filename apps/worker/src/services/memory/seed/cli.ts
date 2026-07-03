#!/usr/bin/env tsx

// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Runnable seeder for the shared global-pool exemplar tier (OPTIONAL harness —
 * NOT part of `vitest run`).
 *
 *   pnpm exec tsx apps/worker/src/services/memory/seed/cli.ts
 *
 * FLAG-GATED / DEFAULT-OFF: with `SHOR_SEED_GLOBAL` unset the CLI performs a DRY
 * RUN — it prints what it WOULD seed (per-tier counts + technique names) and
 * writes nothing. Set `SHOR_SEED_GLOBAL=1` to actually produce output.
 *
 * WRITER WIRING (why JSON, not direct SQL): the worker package deliberately does
 * NOT depend on `pg` — the whole memory write path uses injected ports so the
 * pgvector repositories stay in `apps/web`. Adding `pg` here would break that
 * boundary. So this CLI's `GlobalPoolWriter` embeds each exemplar (via the real
 * `createEmbedClient`) and EMITS a `GlobalPoolInput[]` JSON array; a tiny
 * web-side script then performs the insert:
 *
 *     import { readFileSync } from "node:fs";
 *     import { globalPoolRepo } from "./db/repositories/memory/global-pool.js";
 *     for (const item of JSON.parse(readFileSync(process.argv[2], "utf8")))
 *       await globalPoolRepo.insert(item);  // sourceTenant:null -> public seed
 *
 * Output goes to `SHOR_SEED_OUTPUT` (a file path, or `-` for stdout); default
 * `./seed-global-pool.json`. CAPEC exemplars are included only when
 * `SHOR_CAPEC_STIX_PATH` points at a MITRE CTI STIX bundle (never committed).
 */

import { readFileSync, writeFileSync } from "node:fs";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import { createEmbedClient } from "../embed/index.js";
import { parseCapecStix } from "./capec/parse.js";
import { seedGlobalPool } from "./ingest.js";
import { flagshipManifest } from "./manifest.js";
import type { GlobalPoolWriter, SeedExemplar } from "./types.js";

/** A collected `globalPoolRepo.insert` argument, ready to serialize. */
type PoolInput = Parameters<GlobalPoolWriter["insert"]>[0];

const DEFAULT_OUTPUT = "./seed-global-pool.json";

/** True when a flag env var is truthy (`1`/`true`/`yes`/`on`). */
function flagOn(value: string | undefined): boolean {
	const raw = value?.trim().toLowerCase();
	return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

/** Minimal console logger (self-contained; no heavy imports). */
const cliLogger: ActivityLogger = {
	info: (m, a) => console.log(`[seed] ${m}`, a ?? ""),
	warn: (m, a) => console.warn(`[seed] WARN ${m}`, a ?? ""),
	error: (m, a) => console.error(`[seed] ERROR ${m}`, a ?? ""),
};

/** Load CAPEC exemplars from `SHOR_CAPEC_STIX_PATH`, or `[]` when unset/unreadable. */
function loadCapec(
	env: NodeJS.ProcessEnv,
	log: ActivityLogger,
): SeedExemplar[] {
	const path = env.SHOR_CAPEC_STIX_PATH?.trim();
	if (!path) return [];
	try {
		const bundle: unknown = JSON.parse(readFileSync(path, "utf8"));
		const parsed = parseCapecStix(bundle);
		log.info("loaded CAPEC exemplars", { path, count: parsed.length });
		return parsed;
	} catch (err) {
		log.warn("could not read CAPEC STIX bundle — skipping", {
			path,
			error: err instanceof Error ? err.message : String(err),
		});
		return [];
	}
}

/** Assemble the full candidate set (flagship manifest + optional CAPEC). */
export function collectUnits(
	env: NodeJS.ProcessEnv,
	log: ActivityLogger,
): SeedExemplar[] {
	return [...flagshipManifest(), ...loadCapec(env, log)];
}

/** Count exemplars per novelty tier for the summary line. */
function tierCounts(units: readonly SeedExemplar[]): Record<string, number> {
	const counts: Record<string, number> = {};
	for (const u of units)
		counts[u.noveltyTier] = (counts[u.noveltyTier] ?? 0) + 1;
	return counts;
}

/** Print the dry-run plan (no embed, no write). */
function printDryRun(units: readonly SeedExemplar[]): void {
	console.log("=== SEED DRY RUN (SHOR_SEED_GLOBAL not set) ===");
	console.log(`would seed ${units.length} exemplar(s):`, tierCounts(units));
	for (const u of units) {
		console.log(
			`  - [${u.noveltyTier}] ${u.technique}  (${u.cwe ?? "no-cwe"})`,
		);
	}
	console.log("set SHOR_SEED_GLOBAL=1 to embed + emit GlobalPoolInput[] JSON.");
}

/** A `GlobalPoolWriter` that buffers inserts for a web-side JSON handoff. */
function jsonEmitWriter(): { writer: GlobalPoolWriter; rows: PoolInput[] } {
	const rows: PoolInput[] = [];
	return {
		rows,
		writer: {
			async insert(input) {
				rows.push(input);
				return { id: `seed-${rows.length}` };
			},
		},
	};
}

/** Serialize buffered rows to the output target (`-` => stdout). */
function emit(rows: PoolInput[], target: string): string {
	const json = `${JSON.stringify(rows, null, 2)}\n`;
	if (target === "-") {
		process.stdout.write(json);
		return "(stdout)";
	}
	writeFileSync(target, json, "utf8");
	return target;
}

/** Run the seeder. Returns a process exit code (0 on success/dry-run). */
export async function runSeedCli(
	env: NodeJS.ProcessEnv = process.env,
): Promise<number> {
	const units = collectUnits(env, cliLogger);

	if (!flagOn(env.SHOR_SEED_GLOBAL)) {
		printDryRun(units);
		return 0;
	}

	const embed = createEmbedClient();
	if (!embed.enabled) {
		cliLogger.warn(
			"SHOR_SEED_GLOBAL is on but SHOR_EMBED_URL is unset — no vectors, nothing emitted",
			{ candidates: units.length },
		);
		return 0;
	}

	const { writer, rows } = jsonEmitWriter();
	const result = await seedGlobalPool(units, {
		embed,
		writer,
		logger: cliLogger,
	});
	const target = env.SHOR_SEED_OUTPUT?.trim() || DEFAULT_OUTPUT;
	const where = emit(rows, target);
	cliLogger.info("seed complete", {
		seeded: result.seeded,
		skipped: result.skipped,
		output: where,
	});
	console.log(
		`emitted ${rows.length} GlobalPoolInput row(s) to ${where}; ` +
			"apply web-side via globalPoolRepo.insert (see cli.ts header).",
	);
	return 0;
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
	runSeedCli().then(
		(code) => process.exit(code),
		(err) => {
			cliLogger.error("seed CLI failed", {
				error: err instanceof Error ? err.message : String(err),
			});
			process.exit(1);
		},
	);
}
