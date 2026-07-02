// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import type {
	ErrorMessageResolver,
	FileExistence,
	ValidationRule,
} from "./types.js";

// Pure function to create validation rule.
function createValidationRule(
	predicate: (existence: FileExistence) => boolean,
	errorMessage: ErrorMessageResolver,
	retryable: boolean = true,
): ValidationRule {
	return Object.freeze({ predicate, errorMessage, retryable });
}

// Generate appropriate error message based on which files are missing.
function getExistenceErrorMessage(existence: FileExistence): string {
	const { deliverableExists, queueExists } = existence;

	if (!deliverableExists && !queueExists) {
		return "Analysis failed: Neither deliverable nor queue file exists. Both are required.";
	}
	if (!queueExists) {
		return "Analysis incomplete: Deliverable exists but queue file missing. Both are required.";
	}
	return "Analysis incomplete: Queue exists but deliverable file missing. Both are required.";
}

// Symmetric deliverable rules: queue and deliverable must exist together
// (prevents partial analysis from triggering exploitation).
export const fileExistenceRules: readonly ValidationRule[] = Object.freeze([
	createValidationRule(
		({ deliverableExists, queueExists }) => deliverableExists && queueExists,
		getExistenceErrorMessage,
	),
]);
