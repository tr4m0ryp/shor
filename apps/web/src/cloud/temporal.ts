/**
 * Temporal Cloud client (ADR-019).
 *
 * One workflow per scan; cancellation is the kill switch. The dashboard mints a
 * scan and starts the scan workflow on Temporal Cloud, which launches the
 * per-scan Cloud Run Job (ADR-051).
 *
 * Lazy: the gRPC `Connection`/`Client` are established on first `getTemporalClient()`
 * call, never at import time, so `tsc`/`build` need no live Temporal endpoint.
 * Temporal Cloud is reached over mTLS (client cert/key) or an API key.
 */

import type { Client } from '@temporalio/client';
import { getConfig } from '../config.js';

let clientPromise: Promise<Client> | undefined;

async function buildClient(): Promise<Client> {
  const { temporal } = getConfig();
  const { Client, Connection } = await import('@temporalio/client');

  // mTLS for Temporal Cloud when cert+key are provided; otherwise plaintext
  // (local dev temporalite). API key auth is supported as an alternative.
  const tls =
    temporal.clientCertPath && temporal.clientKeyPath
      ? await loadTls(temporal.clientCertPath, temporal.clientKeyPath)
      : undefined;

  const connection = await Connection.connect({
    address: temporal.address,
    ...(tls ? { tls } : {}),
    ...(temporal.apiKey ? { apiKey: temporal.apiKey } : {}),
  });

  return new Client({ connection, namespace: temporal.namespace });
}

async function loadTls(certPath: string, keyPath: string): Promise<{ clientCertPair: { crt: Buffer; key: Buffer } }> {
  const { readFile } = await import('node:fs/promises');
  const [crt, key] = await Promise.all([readFile(certPath), readFile(keyPath)]);
  return { clientCertPair: { crt, key } };
}

/** Lazily connect (and memoize) the Temporal Cloud client. */
export function getTemporalClient(): Promise<Client> {
  if (!clientPromise) {
    clientPromise = buildClient();
  }
  return clientPromise;
}

/** The task queue scan workflows are dispatched to. */
export function scanTaskQueue(): string {
  return getConfig().temporal.taskQueue;
}

/** Deterministic per-scan workflow id `aegis-<scanId>` (ADR-019). */
export function scanWorkflowId(scanId: string): string {
  return `aegis-${scanId}`;
}

/** Drop the memoized client (tests / reconnect). */
export function resetTemporalClient(): void {
  clientPromise = undefined;
}
