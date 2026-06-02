// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
