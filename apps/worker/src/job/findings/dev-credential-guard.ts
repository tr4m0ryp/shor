// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Dev/test-credential demotion (refinement gate).
 *
 * A secret COMMITTED ON PURPOSE as local/dev scaffolding is not a leaked production
 * secret: real deployments override it (e.g. .NET config keys re-injected as
 * `CanvasLti__Key`/`S3__SigningKey` via Kubernetes secretRefs). Scan 0008 flagged
 * such defaults — marked `// For local testing`, with obviously-fake values like
 * `"blawla…blawla…"` and Mongo `admin/admin` — as CRITICAL "hardcoded key → auth
 * bypass" findings. They are at most a LOW config-hygiene note.
 *
 * This pass demotes a hardcoded-secret finding to `low` when the value is clearly
 * intentional scaffolding: a dev/test marker comment (read from the cited source
 * line when resolvable), a known placeholder value, or a hand-typed "doubled" fake
 * (a value that is its own two identical halves — never a real key). Conservative:
 * a high-entropy, unmarked secret is LEFT ALONE (it may be a genuine leak).
 */

import fs from 'node:fs';
import path from 'node:path';
import type { ActivityLogger } from '../../types/activity-logger.js';
import type { FindingRecord, FindingSeverity } from './types.js';

/** Inline comments / phrases that mark a value as deliberate dev/test scaffolding. */
const DEV_MARKERS: readonly RegExp[] = [
  /for\s+local\s+testing/i,
  /for\s+testing/i,
  /\btest(ing)?[-_\s]only\b/i,
  /\bdev(elopment)?[-_\s]only\b/i,
  /local\s+dev\b/i,
  /do\s+not\s+use\s+in\s+prod/i,
  /\bplaceholder\b/i,
  /replace[-_\s]?me/i,
  /change[-_\s]?me/i,
  /\bdummy\b/i,
  /\bsample\b/i,
];

/** Literal placeholder values that are never real secrets. */
const PLACEHOLDER_VALUES: readonly string[] = [
  'replace-me',
  'replaceme',
  'changeme',
  'change-me',
  'your-key',
  'your_secret',
  'your-secret',
  'placeholder',
  'todo',
];

const NOTE =
  '[DEV/TEST CREDENTIAL — committed intentionally as local/dev scaffolding (test marker / placeholder / non-secret value); production overrides it via deploy-time secrets. Not a leaked production secret; residual is LOW (ensure no deployment ships these defaults).] ';

/** A hardcoded-secret/credential finding (the only class this gate touches). */
function isHardcodedSecretFinding(r: FindingRecord): boolean {
  if (r.cwe === 'CWE-798') return true;
  const t = `${r.title} ${r.evidence} ${r.missing_defense}`.toLowerCase();
  return (
    /hardcoded|hard-coded|hard coded|committed|embedded/.test(t) &&
    /secret|signing key|api key|apikey|credential|password|private key|hmac key/.test(t)
  );
}

/** True when a quoted token in `text` is its own two identical halves (a hand-typed fake). */
function hasDoubledFakeValue(text: string): boolean {
  for (const m of text.matchAll(/["'`]([A-Za-z0-9+/=_-]{16,})["'`]/g)) {
    const v = m[1];
    if (v && v.length % 2 === 0) {
      const half = v.length / 2;
      if (v.slice(0, half) === v.slice(half)) return true;
    }
  }
  return false;
}

/** Best-effort: the cited source line (so a trailing `// For local testing` is seen). */
function citedSourceLine(r: FindingRecord, root: string | undefined): string {
  if (!root) return '';
  try {
    const fileRaw = r.vulnerable_code_location?.file ?? '';
    const m = String(fileRaw).match(/[\w./-]+\.(?:cs|ts|tsx|json|ya?ml|js|config|env)/i);
    if (!m) return '';
    const abs = path.join(root, m[0]);
    if (!fs.existsSync(abs)) return '';
    const line = r.vulnerable_code_location?.line;
    if (typeof line !== 'number' || line <= 0) return '';
    return fs.readFileSync(abs, 'utf8').split('\n')[line - 1] ?? '';
  } catch {
    return '';
  }
}

/**
 * Demote hardcoded-secret findings that are clearly intentional dev/test scaffolding
 * to `low`. Pure + best-effort; non-secret findings and high-entropy unmarked secrets
 * pass through unchanged.
 */
export function demoteDevCredentials(
  records: FindingRecord[],
  analyzedSourceRoot: string | undefined,
  logger: ActivityLogger,
): FindingRecord[] {
  let demoted = 0;
  const out = records.map((r) => {
    if (r.severity === 'low' || r.severity === 'info' || !isHardcodedSecretFinding(r)) return r;
    const hay = `${r.evidence ?? ''}\n${r.safe_poc ?? ''}\n${citedSourceLine(r, analyzedSourceRoot)}`;
    const low = hay.toLowerCase();
    const scaffolding =
      DEV_MARKERS.some((re) => re.test(hay)) ||
      PLACEHOLDER_VALUES.some((v) => low.includes(`"${v}"`) || low.includes(`'${v}'`) || low.includes(`: ${v}`)) ||
      hasDoubledFakeValue(hay);
    if (!scaffolding) return r;
    demoted += 1;
    return {
      ...r,
      severity: 'low' as FindingSeverity,
      dev_credential_scaffolding: true,
      evidence: String(r.evidence ?? '').startsWith('[DEV/TEST CREDENTIAL') ? r.evidence : NOTE + (r.evidence ?? ''),
    };
  });
  if (demoted > 0) logger.info('Demoted intentional dev/test credentials to low', { count: demoted });
  return out;
}
