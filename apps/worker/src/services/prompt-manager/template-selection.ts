// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Select the pre-recon prompt filename. Pre-recon dispatch is clearnet-only,
 * so this always resolves to the clearnet template.
 *
 * Returns the bare filename (including `.txt`) so the caller can `path.join`
 * directly with the prompts directory. The `targetUrl` parameter is retained
 * for interface compatibility with callers.
 */
export function selectPreReconTemplate(_targetUrl: string): string {
	return "pre-recon-code.txt";
}
