// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * File I/O Utilities
 *
 * Core utility functions for file operations including atomic writes,
 * directory creation, and JSON file handling.
 */

import fs from "node:fs/promises";

/**
 * Ensure directory exists (idempotent, race-safe)
 */
export async function ensureDirectory(dirPath: string): Promise<void> {
	try {
		await fs.mkdir(dirPath, { recursive: true });
	} catch (error) {
		// Ignore EEXIST errors (race condition safe)
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
			throw error;
		}
	}
}

/**
 * Atomic write using temp file + rename pattern
 * Guarantees no partial writes or corruption on crash
 */
export async function atomicWrite(
	filePath: string,
	data: object | string,
): Promise<void> {
	const tempPath = `${filePath}.tmp`;
	const content =
		typeof data === "string" ? data : JSON.stringify(data, null, 2);

	try {
		// Write to temp file
		await fs.writeFile(tempPath, content, "utf8");

		// Atomic rename (POSIX guarantee: atomic on same filesystem)
		await fs.rename(tempPath, filePath);
	} catch (error) {
		// Clean up temp file on failure
		try {
			await fs.unlink(tempPath);
		} catch {
			// Ignore cleanup errors
		}
		throw error;
	}
}

/**
 * Read and parse JSON file
 */
export async function readJson<T = unknown>(filePath: string): Promise<T> {
	const content = await fs.readFile(filePath, "utf8");
	return JSON.parse(content) as T;
}

/**
 * Check if file exists
 */
export async function fileExists(filePath: string): Promise<boolean> {
	try {
		await fs.access(filePath);
		return true;
	} catch {
		return false;
	}
}
