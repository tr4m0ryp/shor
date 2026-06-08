// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Adversarial FP-refute panel (T2) — STABLE seam, opt-in (`SHOR_FP_PANEL=1`).
 *
 * Reuses the screen-panel voter primitive (`runVoter` + session-lease pool + the
 * majority `decideVotes` aggregator) to run an N-vote panel over the CONFIRMED +
 * high/critical findings, this time handing each voter the TARGET SOURCE so it can
 * prove a cited guard is actually present. A majority-refute is written to
 * `fp_refute_verdicts.json`; `collectFindings` reads it back (via `applyFpRefuteVerdicts`)
 * and demotes the finding to `refuted_on_review`. DEFAULT: identity — when disabled
 * the panel never runs and the emitted set is byte-for-byte unchanged.
 */

import path from 'node:path';
import { collectFindings } from '../../job/findings/index.js';
import type { FindingCategory } from '../../job/findings/types.js';
import type { AgentContext } from '../../job/pipeline.js';
import {
  buildVerdictEntry,
  createSessionPool,
  lensesForCategory,
  panelSizeForCategory,
  runVoter,
  SCREEN_SESSIONS,
  type ScreenVerdictEntry,
  type ScreenVote,
  type SessionPool,
} from '../screen-panel/index.js';
import type { VoterRunArgs } from '../screen-panel/voter.js';
import { fpRefuteEnabled, writeFpVerdicts } from './io.js';
import { selectFpCandidates } from './select.js';
import { fpRefuteBasePrompt } from './voter.js';

export { FP_REFUTE_FILE, fpRefuteEnabled } from './io.js';
export { applyFpRefuteVerdicts } from './router.js';
export { selectFpCandidates } from './select.js';

/** Lease a session, run one voter, always release — mirrors the screen panel's private helper. */
async function runLeasedVoter(pool: SessionPool, args: Omit<VoterRunArgs, 'session'>): Promise<ScreenVote> {
  const lease = await pool.acquire();
  try {
    return await runVoter({ ...args, session: lease.session });
  } finally {
    lease.release();
  }
}

/**
 * Run the FP-refute panel as a (post-oracle) phase. Opt-in + best-effort: a disabled
 * flag, no candidates, or any failure leaves the findings untouched (never demotes
 * on error). Writes `fp_refute_verdicts.json` for `collectFindings` to apply.
 */
export async function runFpRefutePanel(ctx: AgentContext): Promise<void> {
  if (!fpRefuteEnabled()) return;
  const { params, deliverablesPath, container, logger } = ctx;

  let candidates: ReturnType<typeof selectFpCandidates>;
  try {
    const findings = await collectFindings(deliverablesPath, logger, { analyzedSourceRoot: params.repoPath });
    candidates = selectFpCandidates(findings);
  } catch (err) {
    logger.warn('fp-refute: failed to load candidate findings; skipping panel', {
      error: err instanceof Error ? err.message : String(err),
    });
    return;
  }
  if (candidates.length === 0) {
    writeFpVerdicts(deliverablesPath, [], logger);
    return;
  }

  const pool = createSessionPool(SCREEN_SESSIONS);
  const providerConfig = container.config.providerConfig;
  const deliverablesSubdir = path.relative(params.repoPath, deliverablesPath);

  const entries: ScreenVerdictEntry[] = await Promise.all(
    candidates.map(async (f): Promise<ScreenVerdictEntry> => {
      const category = f.category as FindingCategory;
      const lenses = lensesForCategory(category, panelSizeForCategory(category));
      const basePrompt = fpRefuteBasePrompt(f);
      const votes = await Promise.all(
        lenses.map((lens, i) =>
          runLeasedVoter(pool, {
            basePrompt,
            candidateId: f.id,
            lens,
            voter: i + 1,
            sourceDir: params.repoPath,
            deliverablesSubdir,
            modelTier: 'medium',
            agentLabel: `fp-refute-${f.category}`,
            logger,
            ...(providerConfig !== undefined ? { providerConfig } : {}),
          }),
        ),
      );
      return buildVerdictEntry(f.id, votes);
    }),
  );

  writeFpVerdicts(deliverablesPath, entries, logger);
  const refuted = entries.filter((e) => e.decision === 'refute').length;
  logger.info('fp-refute panel complete', { candidates: candidates.length, refuted });
}
