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
	const lines = [
		`- Login type: ${auth.login_type.toUpperCase()}`,
		`- Username: ${auth.credentials.username}`,
		`- Login URL: ${auth.login_url}`,
	];

	if (auth.credentials?.totp_secret) {
		lines.push("- MFA: TOTP enabled");
	}

	return lines.join("\n");
}
