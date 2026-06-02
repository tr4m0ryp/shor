/**
 * Aegis cloud + data foundation — env-driven configuration.
 *
 * Every value is read from the environment with a safe default so `tsc` and
 * `pnpm build` succeed WITHOUT live GCP credentials. Nothing here touches the
 * network or a live GCP API at import time; the cloud client wrappers under
 * `src/cloud/*` construct their SDK clients lazily on first use.
 *
 * Reference: LAUNCH-SPEC §2 (architecture), §3 (auth/secrets). Mirrors the
 * env-var style of storron's apps/web/src/api/config/env.ts.
 */

function env(name: string, fallback = ''): string {
  const value = process.env[name];
  return value === undefined || value === '' ? fallback : value;
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function envBool(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  return raw === '1' || raw.toLowerCase() === 'true';
}

/** Core GCP project + region (ADR-021). */
export interface GcpConfig {
  readonly projectId: string;
  readonly region: string;
}

/**
 * Cloud SQL for PostgreSQL connection (ADR-020).
 *
 * In Cloud Run we connect over the Cloud SQL Auth Proxy unix socket
 * (`/cloudsql/<INSTANCE_CONNECTION_NAME>`); locally we connect over TCP.
 * `instanceConnectionName` selects the socket path when `host` is empty.
 */
export interface CloudSqlConfig {
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly user: string;
  readonly password: string;
  /** `project:region:instance` — used to derive the unix socket path. */
  readonly instanceConnectionName: string;
  readonly ssl: boolean;
  readonly maxPoolSize: number;
}

/** GCS single-bucket, per-tenant prefix layout (ADR-037). */
export interface StorageConfig {
  readonly bucket: string;
}

/** Temporal Cloud client config (ADR-019). */
export interface TemporalConfig {
  readonly address: string;
  readonly namespace: string;
  readonly taskQueue: string;
  /** mTLS client cert/key, PEM contents or file paths (Temporal Cloud). */
  readonly clientCertPath: string;
  readonly clientKeyPath: string;
  readonly apiKey: string;
}

/** Google Cloud Identity Platform (ADR-016 / ADR-042 / ADR-043). */
export interface IdentityConfig {
  /** GCP project that hosts the Identity Platform / Firebase Auth tenants. */
  readonly projectId: string;
  /** Default IdP tenant id; per-request tenant comes from the verified token. */
  readonly defaultTenantId: string;
  /** Name of the server-minted HTTP-only session cookie. */
  readonly sessionCookieName: string;
  /** Session cookie lifetime in seconds. */
  readonly sessionTtlSeconds: number;
}

/**
 * Server-minted session cookie config (ADR-043).
 *
 * The dashboard verifies the Identity Platform ID token, then mints its own
 * HMAC-signed HTTP-only cookie. `signingSecret` keys that HMAC and MUST be set
 * to a strong random value in any non-local deployment.
 */
export interface SessionConfig {
  /** Name of the server-minted HTTP-only session cookie. */
  readonly cookieName: string;
  /** Session cookie lifetime in seconds. */
  readonly ttlSeconds: number;
  /** HMAC signing secret for the session cookie (`SESSION_SIGNING_SECRET`). */
  readonly signingSecret: string;
}

/** Secret Manager wrapper config (ADR-017 / ADR-045). */
export interface SecretsConfig {
  /** Project that owns the per-(tenant,user,provider) secrets. */
  readonly projectId: string;
  /** Naming prefix; full id is `<prefix>/<tenant>/<user>/<provider>`. */
  readonly prefix: string;
}

/**
 * GitHub App connection config (ADR-039/040/041).
 *
 * One Aegis App, per-tenant installation. The numeric `appId` is non-secret
 * config; the App private key (PEM) is NEVER held here — it lives in Secret
 * Manager and is read on demand via `privateKeySecretRef`. Installation tokens
 * are short-lived and minted per scan.
 */
export interface GithubAppConfig {
  /** Numeric GitHub App id (non-secret). Empty disables github ingest. */
  readonly appId: string;
  /** Secret Manager reference holding the App private key PEM (NO key in env/DB). */
  readonly privateKeySecretRef: string;
  /** Default clone depth for github ingest (ADR-040). */
  readonly cloneDepth: number;
}

export interface AegisConfig {
  readonly env: 'development' | 'production' | 'test';
  readonly gcp: GcpConfig;
  readonly sql: CloudSqlConfig;
  readonly storage: StorageConfig;
  readonly temporal: TemporalConfig;
  readonly identity: IdentityConfig;
  readonly session: SessionConfig;
  readonly secrets: SecretsConfig;
  readonly github: GithubAppConfig;
}

let cached: AegisConfig | undefined;

/**
 * Build (and memoize) the resolved config from the current environment.
 * Lazy + defaulted: importing this module performs no I/O and needs no live
 * GCP credentials.
 */
export function getConfig(): AegisConfig {
  if (cached) return cached;

  const projectId = env('GCP_PROJECT_ID', 'aegis-local');
  const region = env('GCP_REGION', 'us-central1');

  const nodeEnv = env('NODE_ENV', 'development');
  const resolvedEnv: AegisConfig['env'] = nodeEnv === 'production' || nodeEnv === 'test' ? nodeEnv : 'development';

  cached = {
    env: resolvedEnv,
    gcp: { projectId, region },
    sql: {
      host: env('CLOUD_SQL_HOST'),
      port: envInt('CLOUD_SQL_PORT', 5432),
      database: env('CLOUD_SQL_DATABASE', 'aegis'),
      user: env('CLOUD_SQL_USER', 'aegis'),
      password: env('CLOUD_SQL_PASSWORD'),
      instanceConnectionName: env('CLOUD_SQL_INSTANCE_CONNECTION_NAME'),
      ssl: envBool('CLOUD_SQL_SSL', false),
      maxPoolSize: envInt('CLOUD_SQL_MAX_POOL', 10),
    },
    storage: {
      bucket: env('GCS_BUCKET', 'aegis-artifacts'),
    },
    temporal: {
      address: env('TEMPORAL_ADDRESS', 'localhost:7233'),
      namespace: env('TEMPORAL_NAMESPACE', 'default'),
      taskQueue: env('TEMPORAL_TASK_QUEUE', 'aegis-scans'),
      clientCertPath: env('TEMPORAL_CLIENT_CERT_PATH'),
      clientKeyPath: env('TEMPORAL_CLIENT_KEY_PATH'),
      apiKey: env('TEMPORAL_API_KEY'),
    },
    identity: {
      projectId: env('IDENTITY_PLATFORM_PROJECT_ID', projectId),
      defaultTenantId: env('IDENTITY_PLATFORM_TENANT_ID'),
      sessionCookieName: env('SESSION_COOKIE_NAME', 'aegis_session'),
      sessionTtlSeconds: envInt('SESSION_TTL_SECONDS', 3600),
    },
    session: {
      cookieName: env('SESSION_COOKIE_NAME', 'aegis_session'),
      ttlSeconds: envInt('SESSION_TTL_SECONDS', 3600),
      // Local default keeps `tsc`/dev working with no secret set; production
      // MUST override with a strong random value.
      signingSecret: env('SESSION_SIGNING_SECRET', 'aegis-local-dev-session-secret'),
    },
    secrets: {
      projectId: env('SECRET_MANAGER_PROJECT_ID', projectId),
      prefix: env('SECRET_MANAGER_PREFIX', 'aegis'),
    },
    github: {
      appId: env('GITHUB_APP_ID'),
      privateKeySecretRef: env('GITHUB_APP_PRIVATE_KEY_SECRET_REF', 'aegis/github-app/private-key'),
      cloneDepth: envInt('GITHUB_CLONE_DEPTH', 1),
    },
  };

  return cached;
}

/** Test/runtime hook: clear the memoized config so the next read re-reads env. */
export function resetConfig(): void {
  cached = undefined;
}
