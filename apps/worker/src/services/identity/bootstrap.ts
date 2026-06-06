// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Multi-identity bootstrap (task 008) — the runtime provisioning that turns a
 * configured identity set into (a) isolated per-identity Playwright session
 * slots and (b) the `scan_identities.json` manifest the threat-model assembler
 * reads.
 *
 * Invoked ONCE before the prereq loop so every downstream agent — threat-model
 * included — sees the identity set. BEST-EFFORT by contract: it NEVER throws. A
 * config that is unreadable, a session slot that fails to provision, or any
 * other fault degrades gracefully (the offending secondary is dropped; with
 * fewer than two identities the manifest carries the single-identity note). When
 * no `identities[]` is configured the behavior is exactly as before — a primary-
 * only manifest with the single-identity note.
 */

import { ConfigLoaderService } from "../config-loader.js";
import { isErr } from "../../types/result.js";
// Type-only import — erased at compile time, so there is no runtime dependency
// back into `job/pipeline` (mirrors the oracle phase) and no import cycle.
import type { AgentContext } from "../../job/pipeline.js";
import { collectIdentities, type ResolvedIdentity } from "./collect.js";
import { buildIdentityManifest, writeIdentityManifest } from "./manifest.js";
import { playwrightSessionsRoot, provisionIdentitySession } from "./session.js";

/**
 * Provision identity sessions and write the identity manifest. Returns nothing;
 * its effects are the per-identity storage-state slots and `scan_identities.json`.
 */
export async function bootstrapIdentities(ctx: AgentContext): Promise<void> {
	const { params, deliverablesPath, container, logger } = ctx;
	try {
		// 1. Resolve the configured identity set (metadata only — no credentials
		//    are copied out of the config). An unreadable config degrades to the
		//    unauthenticated/single-identity path rather than aborting the scan.
		const loader = new ConfigLoaderService();
		const configResult = await loader.loadOptional(
			params.configPath,
			undefined,
			params.configYaml,
		);
		if (isErr(configResult)) {
			logger.warn(
				"Identity bootstrap: config unreadable; degrading to single-identity coverage",
				{ scanId: params.scanId, error: configResult.error.message },
			);
		}
		const auth = isErr(configResult)
			? null
			: (configResult.value?.authentication ?? null);
		const identities = collectIdentities(auth);

		// 2. Provision each identity's isolated session slot. A per-identity
		//    failure drops only that identity (degrade), never the whole bootstrap.
		const sessionsRoot = playwrightSessionsRoot(
			params.repoPath,
			container.config.deliverablesSubdir,
		);
		const provisioned: ResolvedIdentity[] = [];
		for (const identity of identities) {
			try {
				await provisionIdentitySession(sessionsRoot, identity);
				provisioned.push(identity);
			} catch (err) {
				logger.warn(
					`Identity bootstrap: failed to provision session for "${identity.label}"; dropping from authz coverage`,
					{
						scanId: params.scanId,
						sessionLabel: identity.sessionLabel,
						error: err instanceof Error ? err.message : String(err),
					},
				);
			}
		}

		// 3. Write the label/role-only manifest the assembler reads.
		const manifest = buildIdentityManifest(provisioned);
		const file = await writeIdentityManifest(deliverablesPath, manifest);
		const count = manifest.identities.length;
		logger.info(
			`Identity bootstrap: wrote ${count} identit${count === 1 ? "y" : "ies"} to ${file}`,
			{
				scanId: params.scanId,
				...(manifest.note ? { singleIdentity: true } : {}),
			},
		);
	} catch (err) {
		// Absolute backstop — a missing manifest reads as "(none)" downstream,
		// identical to pre-task-008 behavior. Never propagate.
		logger.error(
			"Identity bootstrap failed; continuing with single-identity coverage",
			{
				scanId: params.scanId,
				error: err instanceof Error ? err.message : String(err),
			},
		);
	}
}
