// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Per-identity Playwright storage-state provisioning.
 *
 * The worker has no programmatic browser: the EXISTING login mechanics are
 * agent-driven — an agent follows the rendered login instructions inside a NAMED
 * Playwright session, and the Playwright MCP persists that session's cookies
 * under `PLAYWRIGHT_MCP_OUTPUT_DIR`. This module provisions, ahead of that, the
 * isolated session SLOT for each identity: a disjoint `identity-<slug>` profile
 * directory plus an empty Playwright storage-state file the login then fills.
 * Because each identity gets its own directory, an authz agent acting as
 * identity A vs B never bleeds cookies across the boundary.
 *
 * No credential is read or written here — only the credential-free session
 * label and a path. Throws on filesystem failure; the bootstrap orchestrator
 * catches per-identity and degrades coverage rather than aborting the scan.
 */

import { fs, path } from "zx";
import type { ResolvedIdentity } from "./collect.js";

/** Empty Playwright `storageState` document — the login flow populates it. */
const EMPTY_STORAGE_STATE = { cookies: [], origins: [] } as const;

/**
 * Resolve the directory the Playwright MCP persists session profiles under,
 * mirroring `PLAYWRIGHT_MCP_OUTPUT_DIR` in `ai/claude-executor/sdk-env.ts`
 * (`<repoPath>/<dirname(deliverablesSubdir)>/.playwright-cli`) so identity state
 * lands beside the phase sessions rather than in a divergent location.
 */
export function playwrightSessionsRoot(
	repoPath: string,
	deliverablesSubdir: string,
): string {
	return path.join(repoPath, path.dirname(deliverablesSubdir), ".playwright-cli");
}

/** Absolute storage-state path for one identity's session slot. */
export function identityStorageStatePath(
	sessionsRoot: string,
	identity: ResolvedIdentity,
): string {
	return path.join(
		sessionsRoot,
		"identities",
		identity.sessionLabel,
		"storage-state.json",
	);
}

/** Outcome of provisioning a single identity's session slot. */
export interface ProvisionedIdentity {
	readonly identity: ResolvedIdentity;
	readonly storageStatePath: string;
}

/**
 * Establish the isolated, credential-free session slot for one identity: ensure
 * its profile directory exists and seed an empty storage-state file if absent
 * (a pre-existing one from a prior pass is left intact). Returns where the state
 * lives so a future browser driver / authz agent can load it.
 */
export async function provisionIdentitySession(
	sessionsRoot: string,
	identity: ResolvedIdentity,
): Promise<ProvisionedIdentity> {
	const storageStatePath = identityStorageStatePath(sessionsRoot, identity);
	await fs.ensureDir(path.dirname(storageStatePath));
	if (!(await fs.pathExists(storageStatePath))) {
		await fs.writeFile(
			storageStatePath,
			`${JSON.stringify(EMPTY_STORAGE_STATE)}\n`,
			"utf8",
		);
	}
	return { identity, storageStatePath };
}
