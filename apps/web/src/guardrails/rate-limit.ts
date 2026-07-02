// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Per-host token-bucket rate limiter — no-DoS guardrail (LAUNCH-SPEC §5.6,
 * OWASP-APTS no-DoS). Caps the request rate the engine can sustain against any
 * single host so an autonomous agent cannot inadvertently hammer a target.
 *
 * Token bucket: each host gets `capacity` tokens that refill at `rps` tokens per
 * second. `acquire(host)` resolves once a token is available (it WAITS rather
 * than rejecting, so legitimate work is paced, not dropped). `tryAcquire(host)`
 * is the non-blocking variant.
 *
 * In-process and per-run by design: each scan runs in its own Cloud Run Job, so
 * a per-process limiter is exactly per-run. No shared state, no I/O at import.
 */

export interface RateLimitConfig {
  /** Sustained requests per second per host. */
  readonly rps: number;
  /** Burst capacity (max tokens). Defaults to `max(1, ceil(rps))`. */
  readonly burst?: number;
  /** Hard ceiling on `acquire` wait before it rejects (ms). Default 30_000. */
  readonly maxWaitMs?: number;
}

const DEFAULT_RPS = 5;
const DEFAULT_MAX_WAIT_MS = 30_000;

interface Bucket {
  tokens: number;
  lastRefill: number;
}

export class RateLimitTimeoutError extends Error {
  constructor(
    readonly host: string,
    readonly waitedMs: number,
  ) {
    super(`rate-limit acquire for host "${host}" exceeded max wait (${waitedMs}ms)`);
    this.name = 'RateLimitTimeoutError';
  }
}

/** A per-host token-bucket limiter. One instance per run. */
export class HostRateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly rps: number;
  private readonly capacity: number;
  private readonly maxWaitMs: number;

  constructor(config: RateLimitConfig = { rps: DEFAULT_RPS }) {
    this.rps = config.rps > 0 ? config.rps : DEFAULT_RPS;
    this.capacity = config.burst && config.burst > 0 ? config.burst : Math.max(1, Math.ceil(this.rps));
    this.maxWaitMs = config.maxWaitMs && config.maxWaitMs > 0 ? config.maxWaitMs : DEFAULT_MAX_WAIT_MS;
  }

  private bucketFor(host: string): Bucket {
    const key = host.toLowerCase();
    let b = this.buckets.get(key);
    if (!b) {
      b = { tokens: this.capacity, lastRefill: Date.now() };
      this.buckets.set(key, b);
    }
    return b;
  }

  private refill(b: Bucket, now: number): void {
    const elapsedSec = (now - b.lastRefill) / 1000;
    if (elapsedSec <= 0) return;
    b.tokens = Math.min(this.capacity, b.tokens + elapsedSec * this.rps);
    b.lastRefill = now;
  }

  /** Non-blocking: consume a token if one is available, else false. */
  tryAcquire(host: string): boolean {
    const b = this.bucketFor(host);
    this.refill(b, Date.now());
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return true;
    }
    return false;
  }

  /**
   * Wait until a token is available for `host`, then consume it. Rejects with
   * `RateLimitTimeoutError` if the wait would exceed `maxWaitMs`.
   */
  async acquire(host: string): Promise<void> {
    const deadline = Date.now() + this.maxWaitMs;
    for (;;) {
      const b = this.bucketFor(host);
      this.refill(b, Date.now());
      if (b.tokens >= 1) {
        b.tokens -= 1;
        return;
      }
      // Tokens needed = 1 - current; time to that many tokens at `rps`.
      const deficit = 1 - b.tokens;
      const waitMs = Math.max(1, Math.ceil((deficit / this.rps) * 1000));
      if (Date.now() + waitMs > deadline) {
        throw new RateLimitTimeoutError(host, this.maxWaitMs);
      }
      await delay(waitMs);
    }
  }

  /** Current available token count for a host (diagnostics/tests). */
  available(host: string): number {
    const b = this.bucketFor(host);
    this.refill(b, Date.now());
    return b.tokens;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

let shared: HostRateLimiter | undefined;

/** Process-wide (= per-run) limiter, lazily constructed from a config. */
export function getRateLimiter(config?: RateLimitConfig): HostRateLimiter {
  if (!shared) shared = new HostRateLimiter(config);
  return shared;
}

/** Test hook: drop the shared limiter so the next read rebuilds it. */
export function resetRateLimiter(): void {
  shared = undefined;
}
