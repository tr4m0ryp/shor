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

/** Split a whitespace-separated command string into argv (drops empty tokens). */
function splitCommand(raw: string): readonly string[] {
  return raw.split(/\s+/).filter((t) => t.length > 0);
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

/**
 * Cloud Run Job-per-scan execution sandbox (ADR-018 / ADR-051).
 *
 * Each scan gets its own Cloud Run Job created with the per-run service identity
 * and the scoped Secret Manager volume mount, then executed. Run-time overrides
 * carry only env vars (the v2 API does not allow overriding identity or volumes
 * at run time), so identity + secret mount are baked into the per-scan Job.
 */
export interface CloudRunConfig {
  /** GCP project that hosts the Cloud Run Jobs. */
  readonly projectId: string;
  /** Region the per-scan Jobs are created/run in. */
  readonly region: string;
  /** Container image (the de-Tor'd worker engine) every scan Job runs. */
  readonly workerImage: string;
  /**
   * Per-run service-identity email TEMPLATE. `{tenantId}` is substituted with
   * the scan's tenant so `secretAccessor` is scoped to that tenant's secrets
   * (ADR-018). When it contains no `{tenantId}`, it is used verbatim.
   */
  readonly runServiceAccount: string;
  /** Optional Serverless VPC Access connector for per-tenant egress (ADR-041). */
  readonly vpcConnector: string;
  /** VPC egress setting: 'all-traffic' | 'private-ranges-only' (ADR-022). */
  readonly vpcEgress: string;
  /** Container entrypoint command run inside the Job (the job entry script). */
  readonly jobCommand: readonly string[];
  /** Per-task CPU request (e.g. '2'). */
  readonly cpu: string;
  /** Per-task memory request (e.g. '4Gi'). */
  readonly memory: string;
  /** Max wall-clock seconds for a single scan task before Cloud Run kills it. */
  readonly taskTimeoutSeconds: number;
  /** Optional CMEK key for per-tenant key custody (ADR-017); empty = Google-managed. */
  readonly encryptionKey: string;
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

/**
 * GitHub OAuth ("Connect with GitHub") web-login config.
 *
 * The browser is redirected to GitHub's authorize endpoint; the callback
 * exchanges the `code` for a user access token, which is stored in the SAME
 * Secret Manager slot the PAT flow uses (repo listing/cloning read it
 * transparently). `clientId`/`clientSecret` are the OAuth App credentials;
 * `oauthEnabled` gates the flow when either is absent.
 */
export interface GithubOauthConfig {
  /** OAuth App client id (`GITHUB_OAUTH_CLIENT_ID`). Empty disables the flow. */
  readonly clientId: string;
  /** OAuth App client secret (`GITHUB_OAUTH_CLIENT_SECRET`). Empty disables the flow. */
  readonly clientSecret: string;
  /** Authorized callback URL (`GITHUB_OAUTH_REDIRECT_URI`); defaults under `publicUrl`. */
  readonly redirectUri: string;
  /** True only when BOTH the client id and secret are configured. */
  readonly oauthEnabled: boolean;
}

/**
 * Two-way Sinas integration config.
 *
 * `engineTriggerToken` is the bearer the external Sinas->engine ingress
 * (`/external/*`) validates, EXACTLY like `sinkToken` guards the findings/progress
 * sink: a secret that MUST be set to a strong random value in any non-local
 * deployment (empty disables the ingress — every request 401s). The `sinas*`
 * trio describes the engine's outbound connection to the user's Sinas instance
 * and is consumed by the sibling mirror task; declared here so all integration
 * env lands in one typed place.
 */
export interface SinasConfig {
  /** Bearer Sinas presents to the `/external/*` ingress (`AEGIS_ENGINE_TRIGGER_TOKEN`). */
  readonly engineTriggerToken: string;
  /** Base URL of the user's Sinas instance the engine mirrors to (`SINAS_URL`). */
  readonly sinasUrl: string;
  /** API key the engine presents to Sinas (`SINAS_API_KEY`). */
  readonly sinasApiKey: string;
  /** Sinas project/namespace the engine writes under (`SINAS_NAMESPACE`). */
  readonly sinasNamespace: string;
}

export interface AegisConfig {
  readonly env: 'development' | 'production' | 'test';
  /**
   * Direct Cloud Run Job launch + findings-sink wiring (ADR-051).
   *
   * The dashboard launches a per-run EXECUTION of a single, pre-created Cloud Run
   * Job (`scanJobName`) with env overrides, then the worker POSTs findings back
   * to the dashboard's own base URL (`publicUrl`) authenticated with a shared
   * service token (`sinkToken`). `sinkToken` is a secret and MUST be set to a
   * strong random value in any non-local deployment.
   */
  /** Pre-created Cloud Run Job that runs the worker image (`CLOUD_RUN_SCAN_JOB`). */
  readonly scanJobName: string;
  /** Shared service token the worker presents to the findings sink (`AEGIS_SINK_TOKEN`). */
  readonly sinkToken: string;
  /** The dashboard's own public base URL the worker POSTs findings to (`AEGIS_PUBLIC_URL`). */
  readonly publicUrl: string;
  /**
   * Env-gated dev login (`AEGIS_DEV_LOGIN`, default false).
   *
   * When true, `GET /auth/me` with no valid session provisions a seeded dev
   * tenant/user, mints a session, and seeds one sample project — so the
   * dashboard can log in and load data WITHOUT the Identity Platform browser
   * flow. Strictly additive and flag-gated; MUST stay false in production.
   */
  readonly devLogin: boolean;
  readonly gcp: GcpConfig;
  readonly sql: CloudSqlConfig;
  readonly storage: StorageConfig;
  readonly temporal: TemporalConfig;
  readonly cloudRun: CloudRunConfig;
  readonly identity: IdentityConfig;
  readonly session: SessionConfig;
  readonly secrets: SecretsConfig;
  readonly github: GithubAppConfig;
  readonly githubOauth: GithubOauthConfig;
  /** Two-way Sinas integration: external-ingress bearer + outbound mirror connection. */
  readonly sinas: SinasConfig;
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

  const publicUrl = env('AEGIS_PUBLIC_URL');
  const githubOauthClientId = env('GITHUB_OAUTH_CLIENT_ID');
  const githubOauthClientSecret = env('GITHUB_OAUTH_CLIENT_SECRET');

  cached = {
    env: resolvedEnv,
    // Env-gated dev login (default OFF). Never enable in production.
    devLogin: envBool('AEGIS_DEV_LOGIN', false),
    // Direct Cloud Run Job launch + findings sink (ADR-051).
    scanJobName: env('CLOUD_RUN_SCAN_JOB', 'aegis-scan-worker'),
    sinkToken: env('AEGIS_SINK_TOKEN'),
    publicUrl,
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
    cloudRun: {
      projectId: env('CLOUD_RUN_PROJECT_ID', projectId),
      region: env('CLOUD_RUN_REGION', region),
      workerImage: env('CLOUD_RUN_WORKER_IMAGE', 'aegis-worker:latest'),
      runServiceAccount: env('CLOUD_RUN_RUN_SERVICE_ACCOUNT', `aegis-scan-{tenantId}@${projectId}.iam.gserviceaccount.com`),
      vpcConnector: env('CLOUD_RUN_VPC_CONNECTOR'),
      vpcEgress: env('CLOUD_RUN_VPC_EGRESS', 'private-ranges-only'),
      jobCommand: splitCommand(env('CLOUD_RUN_JOB_COMMAND', 'node dist/job-entry.js')),
      cpu: env('CLOUD_RUN_CPU', '2'),
      memory: env('CLOUD_RUN_MEMORY', '4Gi'),
      taskTimeoutSeconds: envInt('CLOUD_RUN_TASK_TIMEOUT_SECONDS', 3600),
      encryptionKey: env('CLOUD_RUN_ENCRYPTION_KEY'),
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
    githubOauth: {
      clientId: githubOauthClientId,
      clientSecret: githubOauthClientSecret,
      redirectUri: env('GITHUB_OAUTH_REDIRECT_URI', `${publicUrl}/settings/github/callback`),
      oauthEnabled: githubOauthClientId !== '' && githubOauthClientSecret !== '',
    },
    sinas: {
      // Bearer for the Sinas->engine ingress (empty = ingress disabled, all 401).
      engineTriggerToken: env('AEGIS_ENGINE_TRIGGER_TOKEN'),
      // Outbound mirror connection (consumed by the sibling mirror task).
      sinasUrl: env('SINAS_URL'),
      sinasApiKey: env('SINAS_API_KEY'),
      sinasNamespace: env('SINAS_NAMESPACE', 'pentest'),
    },
  };

  return cached;
}

/** Test/runtime hook: clear the memoized config so the next read re-reads env. */
export function resetConfig(): void {
  cached = undefined;
}
