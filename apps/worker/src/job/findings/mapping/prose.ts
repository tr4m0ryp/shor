// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Human-readable prose synthesis for a `FindingRecord`: the displayed title and
 * the "why not confirmed" validation note. Factored out of `record.ts` to keep
 * each file under the 300-line cap; behavior is verbatim from the pre-split
 * `mapping.ts` (these are NOT changed by Task 001).
 */

import type { FindingCategory, VulnDisposition } from '../types.js';

/** Readable class label per category (the dashboard shows the short code badge). */
const CLASS_LABEL: Record<FindingCategory, string> = {
  injection: 'Injection',
  xss: 'XSS',
  auth: 'Authentication',
  ssrf: 'SSRF',
  authz: 'Authorization',
  logic: 'Business Logic',
  'misconfig-web': 'Security Misconfiguration',
};

/**
 * Humanize a raw `vulnerability_type` token ("Login_Flow_Logic" → "Login Flow
 * Logic", "DOM-based" → "DOM-based"). Underscores become spaces; an all-lowercase
 * word is capitalized, but existing caps (DOM, JWT, IDOR) are preserved.
 */
function humanizeType(vt: string): string {
  return vt
    .replace(/_+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .split(' ')
    .map((w) => (w && /[a-z]/.test(w) && w === w.toLowerCase() ? w.charAt(0).toUpperCase() + w.slice(1) : w))
    .join(' ');
}

/**
 * Expand terse weakness-type codes that are meaningless on their own ("Horizontal"
 * / "Vertical" authz, etc.) into a self-describing phrase. Keyed by the lowercased
 * raw `vulnerability_type`; anything not listed is humanized as-is.
 */
const TYPE_EXPANSION: Record<string, string> = {
  horizontal: 'Horizontal Access Control / IDOR',
  vertical: 'Vertical Privilege Escalation',
  context_workflow: 'Workflow Authorization Bypass',
  service_discovery: 'Internal Service Discovery',
};

/**
 * Synthesize a descriptive finding title from the weakness class + type so a
 * finding is never displayed as the bare category. XSS reads best as "<type>
 * XSS"; other classes get the humanized type, suffixed with the class label when
 * the type alone is not self-describing.
 */
export function synthTitle(category: FindingCategory, vulnerabilityType: string): string {
  const label = CLASS_LABEL[category] ?? category.toUpperCase();
  const expanded = TYPE_EXPANSION[vulnerabilityType.toLowerCase().trim()] ?? vulnerabilityType;
  const h = humanizeType(expanded);
  if (!h) return category === 'xss' ? 'Cross-Site Scripting (XSS)' : `${label} weakness`;
  if (category === 'xss') return /xss|scripting/i.test(h) ? h : `${h} XSS`;
  if (/injection|ssrf|xss|scripting|authoriz|authentic|idor|traversal/i.test(h)) return h;
  return `${h} (${label})`;
}

/**
 * Derive a human-readable explanation of why the finding is not `confirmed`.
 * Pattern-matches the exploitation evidence prose for specific blocking reasons;
 * falls back to a generic label per disposition. Empty for `exploited` findings.
 */
export function synthesizeValidationNote(disposition: VulnDisposition, evidenceText: string): string {
  if (disposition === 'exploited') return '';
  if (disposition === 'unverified_out_of_scope') {
    return 'Excluded — enforcing tier not in analyzed source; could not be verified from this scan';
  }
  if (disposition === 'unverified_screen_rejected') {
    const reason = evidenceText.trim();
    return reason
      ? `Refuted by adversarial screen — ${reason}`
      : 'Refuted — the adversarial screen rejected this hypothesis before exploitation; not a confirmed finding';
  }
  if (disposition === 'blocked') {
    const e = evidenceText.toLowerCase();
    if (/waf|cloudflare|akamai|imperva|block(ed)?\s+by\s+(waf|security|firewall)/.test(e)) {
      return 'Blocked — WAF / security control intercepted the probe';
    }
    if (/rate.?limit|429|too many requests|throttl/.test(e)) {
      return 'Blocked — rate-limited during exploitation attempt';
    }
    if (/internal|vpn|tailscale|private.?network|not externally|requires.*(vpn|internal)/.test(e)) {
      return 'Blocked — endpoint requires internal network access (not externally reachable)';
    }
    if (/401|403|unauthorized|forbidden|authentication required|session required|login required/.test(e)) {
      return 'Blocked — requires authenticated session not available during testing';
    }
    return 'Blocked — security control prevented exploitation; finding unconfirmed';
  }
  // disposition === "queued": no evidence entry for this finding
  return 'Unproven — no live validation evidence produced; finding remains a code-analysis hypothesis';
}
