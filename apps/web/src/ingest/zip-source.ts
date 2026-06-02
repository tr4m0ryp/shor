/**
 * Zip-upload source ingest (LAUNCH-SPEC §4.2, ADR-015/037).
 *
 * Ports storron's `uploads/zip.ts` validation (magic-byte check, size cap) but
 * targets GCS instead of a local `repos/` dir: the uploaded archive is stored
 * verbatim under `objectPrefix(tenant, project, version)` and an immutable
 * `CodebaseVersion` (source `zip`, no git SHA) is minted. Extraction happens
 * later in the per-run sandbox, not here.
 */

import { randomUUID } from 'node:crypto';
import { objectPrefix, putObject } from '../cloud/storage.js';
import { codebaseVersionRepo } from '../db/repositories/index.js';
import type { CodebaseVersion, Project, TenantId } from '../domain/types.js';

/** Default upload cap, mirroring storron's `MAX_ZIP_BYTES` (500 MiB). */
export const MAX_ZIP_BYTES = 500 * 1024 * 1024;

/** Inputs for a zip ingest — the archive bytes plus its target project. */
export interface ZipIngestInput {
  readonly tenantId: TenantId;
  readonly project: Project;
  /** The uploaded zip contents. */
  readonly archive: Buffer;
  /** Original filename (for the provenance sidecar only; sanitized). */
  readonly filename?: string;
  /** Override the default size cap. */
  readonly maxBytes?: number;
}

/**
 * Validate the PKZIP magic bytes (`PK\x03\x04` / empty / spanned variants).
 *
 * Mirrors storron's `isZipFile` but operates on a buffer rather than a file
 * descriptor since the upload is already in memory here.
 */
export function isZipBuffer(buf: Buffer): boolean {
  if (buf.length < 4) return false;
  return buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 0x03 || buf[2] === 0x05 || buf[2] === 0x07);
}

/**
 * Ingest an uploaded zip into an immutable CodebaseVersion.
 *
 * Rejects oversized or non-zip payloads before touching GCS. Stores the archive
 * as `source.zip` plus a provenance sidecar, then mints the version row.
 */
export async function ingestZip(input: ZipIngestInput): Promise<CodebaseVersion> {
  const cap = input.maxBytes ?? MAX_ZIP_BYTES;
  if (input.archive.length === 0) {
    throw new Error('zip ingest: empty upload');
  }
  if (input.archive.length > cap) {
    throw new Error(`zip ingest: upload exceeds ${cap} byte limit`);
  }
  if (!isZipBuffer(input.archive)) {
    throw new Error('zip ingest: uploaded file is not a valid zip archive');
  }

  const versionId = randomUUID();
  const prefix = objectPrefix(input.tenantId, input.project.id, versionId);

  await putObject(`${prefix}source.zip`, input.archive, 'application/zip');
  await putObject(`${prefix}metadata.json`, zipMetadata(input), 'application/json');

  return codebaseVersionRepo.create({
    projectId: input.project.id,
    sourceKind: 'zip',
    gitSha: null,
    gcsPrefix: prefix,
  });
}

/** Provenance sidecar (no secrets); filename is sanitized to a safe basename. */
function zipMetadata(input: ZipIngestInput): string {
  return JSON.stringify(
    {
      sourceKind: 'zip',
      filename: sanitizeFilename(input.filename ?? 'upload.zip'),
      bytes: input.archive.length,
    },
    null,
    2,
  );
}

/** Strip path separators / dotfiles; allow `[A-Za-z0-9._-]` only (storron parity). */
function sanitizeFilename(raw: string): string {
  const cleaned = raw
    .replace(/^\.+/, '')
    .replace(/[^A-Za-z0-9._-]/g, '_')
    .slice(0, 64);
  return cleaned || 'upload.zip';
}
