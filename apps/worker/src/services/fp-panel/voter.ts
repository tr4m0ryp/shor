// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * The per-finding base prompt for an FP-refute voter (T2). Unlike the screen voter
 * (which probes the live target from recon only), this voter is handed the FINDING
 * plus a mandate to OPEN the cited source file and look for affirmative evidence the
 * finding is a false positive. The shared `voterFramingBlock` (appended by
 * `runVoter`) supplies the refute/support/uncertain verdict contract.
 */

import type { FindingRecord } from '../../job/findings/types.js';

/** Build the source-context base prompt for refuting one confirmed finding. */
export function fpRefuteBasePrompt(f: FindingRecord): string {
  const loc = f.vulnerable_code_location;
  const where = loc?.file ? `${loc.file}:${loc.line ?? ''}` : '(no code location given)';
  return [
    '<fp_refute_target>',
    'You are an adversarial reviewer auditing a CONFIRMED security finding for FALSE-POSITIVITY.',
    'The target SOURCE is in your working directory (sourceDir). OPEN the cited file and read the',
    'surrounding code BEFORE deciding — do not judge from the summary alone.',
    '',
    `Finding id:        ${f.id}`,
    `Title:             ${f.title}`,
    `Category / CWE:    ${f.category} / ${f.cwe}`,
    `Severity / conf.:  ${f.severity} / ${f.confidence}`,
    `Cited location:    ${where}`,
    `Claimed missing defense: ${f.missing_defense}`,
    `Evidence (excerpt): ${String(f.evidence ?? '').slice(0, 800)}`,
    '',
    'Emit verdict "refute" ONLY with affirmative SOURCE evidence the finding is wrong, e.g.:',
    '  - the guard/authorization the finding claims is MISSING is actually PRESENT at/near the cited line;',
    '  - the exploit premise is invalid (e.g. it only succeeds for a privileged identity);',
    '  - the cited location is test/mock scaffolding, not the live application;',
    '  - the cited line does not contain the asserted construct (a mis-cite).',
    'Otherwise emit "support" (the finding stands / you could not refute it) or "uncertain".',
    'Quote the exact file:line you read in your `reason`.',
    '</fp_refute_target>',
  ].join('\n');
}
