// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Deliverable Type Definitions
 *
 * Maps deliverable types to their filenames for the save-deliverable CLI.
 */

export enum DeliverableType {
	// Pre-recon agent
	CODE_ANALYSIS = "CODE_ANALYSIS",

	// Recon agent
	RECON = "RECON",

	// Vulnerability analysis agents
	INJECTION_ANALYSIS = "INJECTION_ANALYSIS",
	XSS_ANALYSIS = "XSS_ANALYSIS",
	AUTH_ANALYSIS = "AUTH_ANALYSIS",
	AUTHZ_ANALYSIS = "AUTHZ_ANALYSIS",
	SSRF_ANALYSIS = "SSRF_ANALYSIS",
	LOGIC_ANALYSIS = "LOGIC_ANALYSIS",
	MISCONFIG_WEB_ANALYSIS = "MISCONFIG_WEB_ANALYSIS",

	// Exploitation agents
	INJECTION_EVIDENCE = "INJECTION_EVIDENCE",
	XSS_EVIDENCE = "XSS_EVIDENCE",
	AUTH_EVIDENCE = "AUTH_EVIDENCE",
	AUTHZ_EVIDENCE = "AUTHZ_EVIDENCE",
	SSRF_EVIDENCE = "SSRF_EVIDENCE",
	LOGIC_EVIDENCE = "LOGIC_EVIDENCE",
	MISCONFIG_WEB_EVIDENCE = "MISCONFIG_WEB_EVIDENCE",
}

/**
 * Hard-coded filename mappings from agent prompts
 */
export const DELIVERABLE_FILENAMES: Record<DeliverableType, string> = {
	[DeliverableType.CODE_ANALYSIS]: "pre_recon_deliverable.md",
	[DeliverableType.RECON]: "recon_deliverable.md",
	[DeliverableType.INJECTION_ANALYSIS]: "injection_analysis_deliverable.md",
	[DeliverableType.XSS_ANALYSIS]: "xss_analysis_deliverable.md",
	[DeliverableType.AUTH_ANALYSIS]: "auth_analysis_deliverable.md",
	[DeliverableType.AUTHZ_ANALYSIS]: "authz_analysis_deliverable.md",
	[DeliverableType.SSRF_ANALYSIS]: "ssrf_analysis_deliverable.md",
	[DeliverableType.LOGIC_ANALYSIS]: "logic_analysis_deliverable.md",
	[DeliverableType.MISCONFIG_WEB_ANALYSIS]: "misconfig-web_analysis_deliverable.md",
	[DeliverableType.INJECTION_EVIDENCE]: "injection_exploitation_evidence.md",
	[DeliverableType.XSS_EVIDENCE]: "xss_exploitation_evidence.md",
	[DeliverableType.AUTH_EVIDENCE]: "auth_exploitation_evidence.md",
	[DeliverableType.AUTHZ_EVIDENCE]: "authz_exploitation_evidence.md",
	[DeliverableType.SSRF_EVIDENCE]: "ssrf_exploitation_evidence.md",
	[DeliverableType.LOGIC_EVIDENCE]: "logic_exploitation_evidence.md",
	[DeliverableType.MISCONFIG_WEB_EVIDENCE]: "misconfig-web_exploitation_evidence.md",
};
