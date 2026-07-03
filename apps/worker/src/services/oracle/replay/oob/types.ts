// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Types for the out-of-band (OOB) proof path (spec T8, F14, R6).
 *
 * The oracle proves blind classes (SSRF / RCE / XXE / blind-SQLi) by minting a
 * fresh, request-bound callback host per payload, injecting it, firing the
 * request, and then correlating any DNS/HTTP callback observed by a self-hosted
 * interactsh server (consumed via the `interactsh-client -json` JSONL sidecar).
 *
 * Correlation is boundary-safe and witnessed: a callback proves the exploit ONLY
 * when the interaction's whole DNS labels contain our fresh `nonce`, the
 * request-bound `witness`, AND our session `correlationLabel` — so a third-party
 * scanner / preview-bot that merely hits the base interactsh domain is rejected.
 */

/** Placeholder the exploit agent writes wherever the OOB callback host belongs. */
export const OOB_CALLBACK_PLACEHOLDER = '{{OOB_CALLBACK}}';

/**
 * A per-payload minted correlation token. Fresh for every replay attempt
 * (`fresh token per attempt`, spec R6): the `nonce` is new each time and the
 * `witness` binds the token to the exact fired request.
 */
export interface OobToken {
  /** Fresh random DNS label, unique to this attempt. */
  readonly nonce: string;
  /** Request-bound witness label (hash of the fired request); rejects foreign hits. */
  readonly witness: string;
  /** The base domain's leading label = our interactsh session correlation id. */
  readonly correlationLabel: string;
  /** `<nonce>.<witness>.<baseDomain>` — the host injected into the payload. */
  readonly callbackHost: string;
  /** The interactsh session base domain (`<corr><rand>.<server>`). */
  readonly baseDomain: string;
}

/** A parsed interactsh interaction (one JSONL line from `interactsh-client -json`). */
export interface OobInteraction {
  /** `dns` | `http` | `smtp` | … (lowercased); empty when absent. */
  readonly protocol: string;
  /** Server-assigned correlation id (`unique-id`); empty when absent. */
  readonly correlationId: string;
  /** Whole DNS labels seen in the interaction (from `full-id` + `raw-request` hosts). */
  readonly labels: ReadonlySet<string>;
  /** Callback source IP, for the audit trail only. */
  readonly remoteAddress: string;
  /** Timestamp string as reported, for the audit trail only. */
  readonly timestamp: string;
}

/** Env-derived config for the OOB proof path (all default-off). */
export interface OobConfig {
  /** Self-hosted interactsh server domain (`SHOR_INTERACTSH_SERVER`). */
  readonly server: string;
  /** interactsh-client binary (`SHOR_INTERACTSH_CLIENT`, default `interactsh-client`). */
  readonly clientBin: string;
  /** Optional server auth token (`SHOR_INTERACTSH_TOKEN`) — header-only, never logged. */
  readonly token?: string;
  /** Long poll window: how long to wait for a (possibly second-order) callback. */
  readonly windowMs: number;
  /** Poll interval while waiting for a callback. */
  readonly pollMs: number;
}

/** Options for {@link OobListener.awaitCallback}; all defaulted from config. */
export interface AwaitOptions {
  windowMs?: number;
  pollMs?: number;
  signal?: AbortSignal;
  /** Injectable clock for tests (defaults to `Date.now`). */
  now?: () => number;
  /** Injectable sleep for tests (defaults to a real `setTimeout`). */
  sleep?: (ms: number) => Promise<void>;
}

/**
 * A live interactsh session: the sidecar plus the buffered interactions it has
 * seen. Constructed once per scan (owned by the 008 wiring) and handed to the
 * OOB executor. Fail-open: when the sidecar never came up, `ready` is false and
 * the executor degrades to `not_replayable` (never a `blocked` refutation).
 */
export interface OobListener {
  /** True once the sidecar is up and a base domain is known. */
  readonly ready: boolean;
  /** The interactsh session base domain, or undefined if not (yet) up. */
  baseDomain(): string | undefined;
  /** Resolve to the first buffered interaction matching `token`, or null on timeout. */
  awaitCallback(token: OobToken, opts?: AwaitOptions): Promise<OobInteraction | null>;
  /** Tear down the sidecar process. */
  stop(): Promise<void>;
}
