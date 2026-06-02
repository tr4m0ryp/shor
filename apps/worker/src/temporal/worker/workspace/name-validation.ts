// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/** Validates a workspace name (1-128 chars, alphanumeric/hyphen/underscore, alphanumeric start). */
export function isValidWorkspaceName(name: string): boolean {
	return /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/.test(name);
}
