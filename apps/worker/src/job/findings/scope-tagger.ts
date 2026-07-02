// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Scaffolding / out-of-scope-target tagger (T2 / A1).
 *
 * The scan harness injects its own mock identity provider and credentials. An
 * "exploit" against that scaffolding (the mock OIDC on :8090, a host with no repo
 * source, anything the reachability pass marked HARNESS_ONLY) is a FALSE exploit
 * about the test double, not the target. This pass tags such findings
 * `in_scope=false` and — stripping the gate-bypass that `exploited` normally earns
 * — demotes them to the terminal `out_of_scope_target` disposition so the gate
 * routes them to the manual-review appendix. Nothing is deleted.
 *
 * Runs BEFORE mapping (on `NormalizedVuln`), so the scoring layer (T1) sees
 * `in_scope=false` and never reads a scaffolding finding as confirmed/critical.
 */

import { CATEGORY_META, firstString } from './category-meta.js';
import type { NormalizedVuln, VulnDisposition } from './types.js';

/**
 * Strong scaffolding signals in a finding's raw location string. Deliberately does
 * NOT match a bare "mock" — the target legitimately ships files like
 * `MockUserService.cs`; only "mock <auth-thing>" phrasing and the harness's mock
 * OIDC port (:8090) / explicit "no source" / "BLACK-BOX" markers qualify.
 */
const SCAFFOLD_LOCATION = /no source in repository|black-?box|:8090\b|mock (oidc|idp|auth|identity|provider|server)/i;

/** Dispositions that already carry a terminal "set aside" reason — do not overwrite. */
function isTerminalSetAside(d: VulnDisposition | undefined): boolean {
  return d === 'unverified_out_of_scope' || d === 'unverified_screen_rejected' || d === 'out_of_scope_target';
}

/** Raw location string for a vuln, read with the same keys the mapper uses. */
function rawLocation(vuln: NormalizedVuln): string {
  const meta = CATEGORY_META[vuln.category];
  return firstString(vuln.raw, meta.locationKeys) || firstString(vuln.raw, meta.endpointKeys);
}

/** Reachability stamped on the raw queue entry by the reachability pass, if any. */
function rawReachability(vuln: NormalizedVuln): string {
  const r = vuln.raw.reachability;
  return typeof r === 'string' ? r : '';
}

/** A finding whose evidence targets the harness scaffolding rather than the app. */
export function isOutOfScopeTarget(vuln: NormalizedVuln): boolean {
  if (rawReachability(vuln).toUpperCase() === 'HARNESS_ONLY') return true;
  return SCAFFOLD_LOCATION.test(rawLocation(vuln));
}

/**
 * Mark every scaffolding/out-of-scope finding `in_scope=false` and demote it to
 * `out_of_scope_target` (unless it already carries a terminal set-aside reason).
 * Mutates in place, like the gates in {@link ./gating.ts}. A genuine in-scope
 * finding is left completely untouched (absence of `in_scope` means "unknown").
 */
export function tagScope(vulns: NormalizedVuln[]): void {
  for (const vuln of vulns) {
    if (!isOutOfScopeTarget(vuln)) continue;
    vuln.in_scope = false;
    if (!isTerminalSetAside(vuln.disposition)) {
      vuln.disposition = 'out_of_scope_target';
    }
  }
}
