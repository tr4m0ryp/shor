/**
 * Google Cloud Storage wrapper (ADR-037).
 *
 * Single bucket, per-tenant prefix:
 *   gs://<bucket>/<tenantId>/<projectId>/<versionId>/...
 * IAM Conditions (`resource.name.startsWith`) enforce per-tenant isolation; we
 * never use a bucket per tenant (GCS soft bucket limit). Artifacts lifecycle-
 * delete after 90 days (ADR-038), configured on the bucket itself.
 *
 * Lazy client: the `Storage` SDK client is constructed on first use, never at
 * import time, so `tsc`/`build` need no live GCP credentials.
 */

import type { Storage } from '@google-cloud/storage';
import { getConfig } from '../config.js';

let storage: Storage | undefined;

async function getClient(): Promise<Storage> {
  if (!storage) {
    const mod = await import('@google-cloud/storage');
    storage = new mod.Storage();
  }
  return storage;
}

/** Per-tenant object key prefix `<tenantId>/<projectId>/<versionId>/`. */
export function objectPrefix(tenantId: string, projectId: string, versionId: string): string {
  return `${tenantId}/${projectId}/${versionId}/`;
}

/** Fully-qualified `gs://` URI for a prefix or object under the configured bucket. */
export function gsUri(objectPath: string): string {
  const { bucket } = getConfig().storage;
  return `gs://${bucket}/${objectPath}`;
}

function bucketName(): string {
  return getConfig().storage.bucket;
}

/** Upload a buffer/string to `<prefix><name>` under the configured bucket. */
export async function putObject(
  objectKey: string,
  body: Buffer | string,
  contentType = 'application/octet-stream',
): Promise<string> {
  const client = await getClient();
  const file = client.bucket(bucketName()).file(objectKey);
  await file.save(typeof body === 'string' ? Buffer.from(body) : body, {
    contentType,
    resumable: false,
  });
  return gsUri(objectKey);
}

/** Download an object as a Buffer; returns `null` when it does not exist. */
export async function getObject(objectKey: string): Promise<Buffer | null> {
  const client = await getClient();
  const file = client.bucket(bucketName()).file(objectKey);
  try {
    const [contents] = await file.download();
    return contents;
  } catch (err) {
    if (isNotFound(err)) return null;
    throw err;
  }
}

/** List object keys under a prefix (e.g. one version's artifacts). */
export async function listObjects(prefix: string): Promise<string[]> {
  const client = await getClient();
  const [files] = await client.bucket(bucketName()).getFiles({ prefix });
  return files.map((f) => f.name);
}

/** Delete a single object. No-op if it does not exist. */
export async function deleteObject(objectKey: string): Promise<void> {
  const client = await getClient();
  try {
    await client.bucket(bucketName()).file(objectKey).delete();
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
}

/**
 * Generate a V4 signed URL for time-limited read access to an object (e.g. a
 * dashboard artifact download link). `ttlSeconds` defaults to 15 minutes.
 */
export async function signedReadUrl(objectKey: string, ttlSeconds = 900): Promise<string> {
  const client = await getClient();
  const [url] = await client
    .bucket(bucketName())
    .file(objectKey)
    .getSignedUrl({
      version: 'v4',
      action: 'read',
      expires: Date.now() + ttlSeconds * 1000,
    });
  return url;
}

function isNotFound(err: unknown): boolean {
  return typeof err === 'object' && err !== null && 'code' in err && (err as { code: unknown }).code === 404;
}
