// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Minimal Result type for explicit error handling.
 *
 * A discriminated union that makes error handling explicit without adding
 * heavy machinery. Used in key modules (config loading, agent execution,
 * queue validation) where callers need to make decisions based on error type.
 */

/**
 * Success variant of Result
 */
export interface Ok<T> {
	readonly ok: true;
	readonly value: T;
}

/**
 * Error variant of Result
 */
export interface Err<E> {
	readonly ok: false;
	readonly error: E;
}

/**
 * Result type - either Ok with a value or Err with an error
 */
export type Result<T, E> = Ok<T> | Err<E>;

/**
 * Create a success Result
 */
export function ok<T>(value: T): Ok<T> {
	return { ok: true, value };
}

/**
 * Create an error Result
 */
export function err<E>(error: E): Err<E> {
	return { ok: false, error };
}

/**
 * Type guard for Ok variant
 */
export function isOk<T, E>(result: Result<T, E>): result is Ok<T> {
	return result.ok === true;
}

/**
 * Type guard for Err variant
 */
export function isErr<T, E>(result: Result<T, E>): result is Err<E> {
	return result.ok === false;
}
