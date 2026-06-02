// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { VulnType } from "../../types/agents.js";
import type { Result } from "../../types/result.js";
import type { PentestError } from "../error-handling.js";

export type { ExploitationDecision, VulnType } from "../../types/agents.js";

export interface VulnTypeConfigItem {
	deliverable: string;
	queue: string;
}

export type VulnTypeConfig = Record<VulnType, VulnTypeConfigItem>;

export type ErrorMessageResolver =
	| string
	| ((existence: FileExistence) => string);

export interface ValidationRule {
	predicate: (existence: FileExistence) => boolean;
	errorMessage: ErrorMessageResolver;
	retryable: boolean;
}

export interface FileExistence {
	deliverableExists: boolean;
	queueExists: boolean;
}

export interface PathsBase {
	vulnType: VulnType;
	deliverable: string;
	queue: string;
	sourceDir: string;
}

export interface PathsWithExistence extends PathsBase {
	existence: FileExistence;
}

export interface PathsWithQueue extends PathsWithExistence {
	queueData: QueueData;
}

export interface PathsWithError {
	error: PentestError;
}

export interface QueueData {
	vulnerabilities: unknown[];
	[key: string]: unknown;
}

export interface QueueValidationResult {
	valid: boolean;
	data: QueueData | null;
	error: string | null;
}

/** Result type for safe validation - explicit error handling. */
export type SafeValidationResult = Result<
	import("../../types/agents.js").ExploitationDecision,
	PentestError
>;
