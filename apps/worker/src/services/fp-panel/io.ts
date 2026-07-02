// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * IO + opt-in gate for the adversarial FP-refute panel (T2). The panel writes
 * `fp_refute_verdicts.json` (the same `ScreenVerdictEntry[]` shape the screen panel
 * uses); `collectFindings` reads back the refuted ids and demotes them.
 */

import fs from 'node:fs';
import path from 'node:path';
import { canonicalVulnId } from '../../job/findings/evidence.js';
import type { ActivityLogger } from '../../types/activity-logger.js';
import type { ScreenVerdictEntry } from '../screen-panel/index.js';

export const FP_REFUTE_FILE = 'fp_refute_verdicts.json';

/**
 * ON by default, gated on provider auth (mirrors the dedup judge): refuting false
 * positives is a core part of refinement. Opt-OUT with `SHOR_FP_PANEL=0`. With no
 * provider configured (tests, unconfigured runs) it stays off and behavior is
 * byte-identical. The panel's voters run on DeepSeek, so DeepSeek auth alone enables it.
 */
export function fpRefuteEnabled(): boolean {
  if (process.env.SHOR_FP_PANEL === '0') return false;
  return Boolean(process.env.CLAUDE_CODE_OAUTH_TOKEN || process.env.ANTHROPIC_API_KEY || process.env.DEEPSEEK_API_KEY);
}

/** Persist the panel's verdict entries. Best-effort; a write failure never throws. */
export function writeFpVerdicts(deliverablesPath: string, entries: ScreenVerdictEntry[], logger: ActivityLogger): void {
  try {
    fs.writeFileSync(path.join(deliverablesPath, FP_REFUTE_FILE), `${JSON.stringify(entries, null, 2)}\n`);
  } catch (err) {
    logger.warn('Failed to write fp-refute verdicts', { error: err instanceof Error ? err.message : String(err) });
  }
}

/** Pull the refuting voter's reason from a vote array, or a generic fallback. */
function refuteReason(votes: unknown): string {
  if (Array.isArray(votes)) {
    for (const v of votes) {
      if (v && typeof v === 'object' && (v as { verdict?: unknown }).verdict === 'refute') {
        const r = (v as { reason?: unknown }).reason;
        if (typeof r === 'string' && r.trim() !== '') return r;
      }
    }
  }
  return 'adversarial source-aware panel refuted this confirmed finding';
}

/**
 * Read `fp_refute_verdicts.json` into a canonical-id-keyed `{ id -> reason }` map of
 * the entries the panel MAJORITY-REFUTED. Tolerates absence / malformed JSON → empty.
 */
export function readFpRefutedIds(deliverablesPath: string, logger: ActivityLogger): Map<string, string> {
  const out = new Map<string, string>();
  const full = path.join(deliverablesPath, FP_REFUTE_FILE);
  try {
    if (!fs.existsSync(full)) return out;
    const parsed: unknown = JSON.parse(fs.readFileSync(full, 'utf8'));
    if (!Array.isArray(parsed)) return out;
    for (const e of parsed) {
      if (!e || typeof e !== 'object') continue;
      const id = (e as { id?: unknown }).id;
      const decision = (e as { decision?: unknown }).decision;
      if (typeof id === 'string' && decision === 'refute') {
        out.set(canonicalVulnId(id), refuteReason((e as { votes?: unknown }).votes));
      }
    }
  } catch (err) {
    logger.warn('Failed to read fp-refute verdicts; none applied', {
      error: err instanceof Error ? err.message : String(err),
    });
  }
  return out;
}
