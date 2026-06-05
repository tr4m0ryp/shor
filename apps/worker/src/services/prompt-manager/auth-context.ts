// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { DistributedConfig } from "../../types/config.js";

/**
 * Render the `{{AUTH_CONTEXT}}` block: a short summary of how the agent should
 * authenticate against the target, or a sentinel string when no auth is set.
 */
export function buildAuthContext(config: DistributedConfig | null): string {
	if (!config?.authentication) {
		return "No authentication configured - unauthenticated testing only";
	}

	const auth = config.authentication;
	// ADR-050: never interpolate the plaintext username (or any credential) into
	// prompt text. Report only that a credential is configured; the runtime
	// resolves the value out-of-band via the {{SHOR_LOGIN_*}} seam tokens.
	const lines = [
		`- Login type: ${auth.login_type.toUpperCase()}`,
		`- Username: ${auth.credentials?.username ? "configured (injected at runtime)" : "not configured"}`,
		`- Login URL: ${auth.login_url}`,
	];

	if (auth.credentials?.totp_secret) {
		lines.push("- MFA: TOTP enabled");
	}

	// The credential + login mechanism above are the PENTEST HARNESS'S OWN
	// authorized access path — scaffolding we configured so the scanner can reach
	// authenticated functionality. It is NOT part of the application's threat model
	// and MUST NOT be reported as a vulnerability. Without this rail, agents flag
	// the access path they were handed (e.g. "the test API key is enumerable", "no
	// rate limit on the login we use", "hard-coded pentest credential") — noise
	// about our own tooling, not the target.
	lines.push(
		"",
		"IMPORTANT — this access path is HARNESS SCAFFOLDING, not a finding:",
		"- The credential and login mechanism described above were provisioned by the",
		"  pentest harness solely to grant the scanner authenticated access. Treat them",
		"  as a trusted given.",
		"- NEVER report a vulnerability whose subject is this injected test credential or",
		"  the login mechanism used to obtain scanner access — not its strength,",
		"  guessability, enumeration/timing behaviour, rate-limiting, storage, or the fact",
		"  that it exists. These are out of scope.",
		"- Instead, test the APPLICATION'S REAL end-user authentication and authorization",
		"  (the flows genuine users go through). Use the harness credential only as a means",
		"  to reach and exercise those real flows.",
	);

	return lines.join("\n");
}
