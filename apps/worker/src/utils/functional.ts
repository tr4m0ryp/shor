// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Functional Programming Utilities
 *
 * Generic functional composition patterns for async operations.
 */

// biome-ignore lint/suspicious/noExplicitAny: pipeline functions need flexible typing for composition
type PipelineFunction = (x: any) => any | Promise<any>;

/**
 * Async pipeline that passes result through a series of functions.
 * Clearer than reduce-based pipe and easier to debug.
 */
export async function asyncPipe<TResult>(
	initial: unknown,
	...fns: PipelineFunction[]
): Promise<TResult> {
	let result = initial;
	for (const fn of fns) {
		result = await fn(result);
	}
	return result as TResult;
}
