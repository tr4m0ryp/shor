// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * interactsh sidecar listener (spec T8, F14, R6).
 *
 * Runs the official `interactsh-client -json` binary against a SELF-HOSTED
 * interactsh server (never the public oast pools), reads its JSONL stdout line by
 * line, buffers each interaction, and detects the session base domain the client
 * prints at startup. `awaitCallback` scans the buffer over a LONG poll window so
 * that second-order callbacks arriving late are not missed — a stock scan with
 * `SHOR_OOB` unset never starts the sidecar.
 *
 * We consume the client binary (do NOT reimplement its RSA/AES crypto). Fail-open
 * everywhere: a missing binary / spawn failure leaves `ready === false`, and the
 * executor degrades to `not_replayable` rather than refuting a blind finding.
 * ADR-050: the server token is passed as a process arg only, never logged.
 */

import { type ChildProcess, spawn } from 'node:child_process';
import type { ActivityLogger } from '../../../../types/activity-logger.js';
import { matchInteraction, parseInteraction } from './correlate.js';
import type { AwaitOptions, OobConfig, OobInteraction, OobListener, OobToken } from './types.js';

/** Long default window: second-order callbacks arrive late — NEVER a 5s window. */
const DEFAULT_WINDOW_MS = 45_000;
const DEFAULT_POLL_MS = 1_000;
/** Cap buffered interactions so a noisy server cannot exhaust memory. */
const MAX_BUFFER = 1_000;

const NOOP_LOGGER: ActivityLogger = { info() {}, warn() {}, error() {} };
const realSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** A minimal spawn seam so tests can drive the sidecar without the real binary. */
export type SpawnFn = (bin: string, args: string[]) => ChildProcess;

/**
 * Read the OOB config from env; `undefined` (=> the executor is a no-op) unless
 * `SHOR_OOB=1` AND a self-hosted `SHOR_INTERACTSH_SERVER` is set. Default-off so a
 * stock scan is unchanged.
 */
export function readOobConfig(env: NodeJS.ProcessEnv = process.env): OobConfig | undefined {
  if (env.SHOR_OOB !== '1') return undefined;
  const server = env.SHOR_INTERACTSH_SERVER?.trim();
  if (!server) return undefined;
  const cfg: OobConfig = {
    server: server.replace(/^\.+|\.+$/g, '').toLowerCase(),
    clientBin: env.SHOR_INTERACTSH_CLIENT?.trim() || 'interactsh-client',
    windowMs: positiveInt(env.SHOR_OOB_WINDOW_MS, DEFAULT_WINDOW_MS),
    pollMs: positiveInt(env.SHOR_OOB_POLL_MS, DEFAULT_POLL_MS),
  };
  const token = env.SHOR_INTERACTSH_TOKEN?.trim();
  return token ? { ...cfg, token } : cfg;
}

function positiveInt(raw: string | undefined, fallback: number): number {
  const n = Number.parseInt(raw ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/** A host printed by the client whose leading label is long enough to be a payload. */
function detectBaseDomain(line: string, server: string): string | undefined {
  const re = new RegExp(`[a-z0-9]{20,}(?:\\.[a-z0-9-]+)*\\.${escapeRe(server)}`, 'i');
  return line.toLowerCase().match(re)?.[0];
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Mutable state shared with the returned {@link OobListener} view. */
interface State {
  baseDomain?: string;
  readonly buffer: OobInteraction[];
  child?: ChildProcess;
  stopped: boolean;
}

/** Feed one stdout line into the state: buffer interactions, detect the base domain. */
function ingestLine(line: string, cfg: OobConfig, state: State, logger: ActivityLogger): void {
  const interaction = parseInteraction(line);
  if (interaction) {
    state.buffer.push(interaction);
    if (state.buffer.length > MAX_BUFFER) state.buffer.shift();
    return;
  }
  if (!state.baseDomain) {
    const base = detectBaseDomain(line, cfg.server);
    if (base) {
      state.baseDomain = base;
      // Log the base domain only — never the server token (ADR-050).
      logger.info('OOB: interactsh session ready', { baseDomain: base });
    }
  }
}

/**
 * Start the interactsh sidecar and return a live {@link OobListener}. Never
 * throws: a spawn failure logs and yields a listener with `ready === false`.
 * `spawnFn` is injectable for tests.
 */
export function startInteractshListener(
  cfg: OobConfig,
  logger: ActivityLogger = NOOP_LOGGER,
  spawnFn: SpawnFn = defaultSpawn,
): OobListener {
  const state: State = { buffer: [], stopped: false };
  const args = ['-json', '-server', cfg.server];
  if (cfg.token) args.push('-token', cfg.token);

  try {
    const child = spawnFn(cfg.clientBin, args);
    state.child = child;
    let carry = '';
    child.stdout?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      carry += chunk;
      const lines = carry.split(/\r?\n/);
      carry = lines.pop() ?? '';
      for (const line of lines) ingestLine(line, cfg, state, logger);
    });
    child.on('error', (err: Error) => {
      logger.warn('OOB: interactsh sidecar error (degrading to not_replayable)', {
        error: err.message,
      });
    });
  } catch (err) {
    logger.warn('OOB: failed to start interactsh sidecar (OOB proof disabled)', {
      error: err instanceof Error ? err.message : String(err),
    });
  }

  return {
    get ready() {
      return state.baseDomain !== undefined && !state.stopped;
    },
    baseDomain: () => state.baseDomain,
    awaitCallback: (token, opts) => awaitCallback(state, cfg, token, opts),
    stop: async () => {
      state.stopped = true;
      try {
        state.child?.kill();
      } catch {
        // best-effort teardown
      }
    },
  };
}

function defaultSpawn(bin: string, args: string[]): ChildProcess {
  return spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
}

/**
 * Poll the buffer for a witnessed callback over a long window. Returns the first
 * matching interaction, or null when the window elapses / the signal aborts.
 * Never finalizes "no proof" on a short window — the window is long by default so
 * late (second-order) callbacks still count.
 */
async function awaitCallback(
  state: State,
  cfg: OobConfig,
  token: OobToken,
  opts: AwaitOptions = {},
): Promise<OobInteraction | null> {
  const windowMs = opts.windowMs ?? cfg.windowMs;
  const pollMs = opts.pollMs ?? cfg.pollMs;
  const now = opts.now ?? Date.now;
  const sleep = opts.sleep ?? realSleep;
  const deadline = now() + windowMs;

  for (;;) {
    const hit = state.buffer.find((i) => matchInteraction(token, i));
    if (hit) return hit;
    if (opts.signal?.aborted || state.stopped) return null;
    if (now() >= deadline) return null;
    await sleep(pollMs);
  }
}
