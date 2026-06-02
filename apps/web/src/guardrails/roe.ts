/**
 * Rules of Engagement (RoE) — machine-parseable per-target scope contract
 * (LAUNCH-SPEC §5.6, §3.3; ADR-008 / ADR-022; OWASP-APTS scope enforcement).
 *
 * The RoE is the authoritative answer to "is this URL in scope?". It is
 * validated once before a run (`validateRoe`) and consulted again immediately
 * before EVERY network action (`assertInScope`) — both the control plane
 * (dashboard) and the worker engine call `assertInScope` so an in-flight agent
 * can never reach a host the operator did not authorize.
 *
 * Design principles:
 *   - DEFAULT-DENY. An empty/invalid allowlist authorizes nothing.
 *   - Host + scheme + path allowlist; out-of-scope hosts are rejected outright.
 *   - Pure + dependency-free so the identical module compiles in both packages
 *     (the worker keeps its own copy; the shape is the contract).
 *
 * This module performs no I/O and constructs no clients — importing it is safe
 * with no live credentials.
 */

/** Schemes an RoE may authorize. We never authorize anything but http(s). */
export type RoeScheme = 'http' | 'https';

export const ROE_SCHEMES: readonly RoeScheme[] = ['http', 'https'] as const;

/**
 * One in-scope host rule. A request matches when its host matches `host`
 * (optionally including subdomains), its scheme is allowed, and its path is
 * under one of `pathPrefixes` (or `pathPrefixes` is empty = whole host).
 */
export interface RoeHostRule {
  /** Lowercase hostname, e.g. `app.example.com`. No scheme, no port, no path. */
  readonly host: string;
  /** When true, `*.host` subdomains are also in scope. Default false. */
  readonly includeSubdomains?: boolean;
  /** Allowed schemes for this host. Empty = `https` only (safe default). */
  readonly schemes?: readonly RoeScheme[];
  /** Allowed path prefixes (`/api`, `/`). Empty = entire host in scope. */
  readonly pathPrefixes?: readonly string[];
  /** Allowed ports. Empty = scheme default port only (80/443). */
  readonly ports?: readonly number[];
}

/** The full per-target Rules of Engagement document. */
export interface Roe {
  /** RoE schema version (forward-compat). */
  readonly version: 1;
  /** Scan/target this RoE governs (for audit correlation). */
  readonly targetUrl: string;
  /** The host allowlist. DEFAULT-DENY: an empty list authorizes nothing. */
  readonly allowedHosts: readonly RoeHostRule[];
  /**
   * Hard deny-list applied AFTER the allowlist — hosts/CIDRs that are never in
   * scope even if an allow rule would match (e.g. shared infra). Optional.
   */
  readonly deniedHosts?: readonly string[];
}

/** A validated RoE — branded so callers cannot pass an unchecked document. */
export type ValidatedRoe = Roe & { readonly __validated: true };

export interface RoeValidationError {
  readonly path: string;
  readonly message: string;
}

export class RoeViolationError extends Error {
  constructor(
    message: string,
    readonly url: string,
  ) {
    super(message);
    this.name = 'RoeViolationError';
  }
}

const DEFAULT_PORT: Record<RoeScheme, number> = { http: 80, https: 443 };

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * Validate an RoE document. Returns the branded `ValidatedRoe` on success or a
 * list of structured errors. Rejects an empty allowlist (default-deny would
 * make the RoE useless and is almost always a config mistake).
 */
export function validateRoe(roe: Roe): { ok: true; roe: ValidatedRoe } | { ok: false; errors: RoeValidationError[] } {
  const errors: RoeValidationError[] = [];

  if (roe.version !== 1) {
    errors.push({ path: 'version', message: 'unsupported RoE version (expected 1)' });
  }
  if (!roe.targetUrl || !isParseableUrl(roe.targetUrl)) {
    errors.push({ path: 'targetUrl', message: 'targetUrl must be an absolute http(s) URL' });
  }
  if (!Array.isArray(roe.allowedHosts) || roe.allowedHosts.length === 0) {
    errors.push({ path: 'allowedHosts', message: 'allowedHosts must be a non-empty allowlist (default-deny)' });
  } else {
    roe.allowedHosts.forEach((rule, i) => validateHostRule(rule, `allowedHosts[${i}]`, errors));
  }

  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, roe: { ...roe, __validated: true } };
}

function validateHostRule(rule: RoeHostRule, path: string, errors: RoeValidationError[]): void {
  if (!rule.host || normalizeHost(rule.host) === '') {
    errors.push({ path: `${path}.host`, message: 'host is required' });
  } else if (/[/:\s]/.test(rule.host)) {
    errors.push({ path: `${path}.host`, message: 'host must not contain scheme, port, path, or whitespace' });
  }
  for (const s of rule.schemes ?? []) {
    if (!ROE_SCHEMES.includes(s)) {
      errors.push({ path: `${path}.schemes`, message: `unsupported scheme "${s}"` });
    }
  }
  for (const p of rule.pathPrefixes ?? []) {
    if (!p.startsWith('/')) {
      errors.push({ path: `${path}.pathPrefixes`, message: `path prefix "${p}" must start with "/"` });
    }
  }
  for (const port of rule.ports ?? []) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      errors.push({ path: `${path}.ports`, message: `port "${port}" is out of range` });
    }
  }
}

function isParseableUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

function hostMatches(rule: RoeHostRule, host: string): boolean {
  const ruleHost = normalizeHost(rule.host);
  if (host === ruleHost) return true;
  if (rule.includeSubdomains === true) return host.endsWith(`.${ruleHost}`);
  return false;
}

function schemeAllowed(rule: RoeHostRule, scheme: RoeScheme): boolean {
  const allowed = rule.schemes && rule.schemes.length > 0 ? rule.schemes : (['https'] as const);
  return allowed.includes(scheme);
}

function pathAllowed(rule: RoeHostRule, path: string): boolean {
  const prefixes = rule.pathPrefixes ?? [];
  if (prefixes.length === 0) return true;
  return prefixes.some((p) => path === p || path.startsWith(p.endsWith('/') ? p : `${p}/`) || path.startsWith(p));
}

function portAllowed(rule: RoeHostRule, scheme: RoeScheme, port: number): boolean {
  const ports = rule.ports ?? [];
  if (ports.length === 0) return port === DEFAULT_PORT[scheme];
  return ports.includes(port);
}

/**
 * Assert a URL is in scope per the RoE. Throws `RoeViolationError` on any
 * violation (unparseable URL, non-http(s) scheme, denied host, or no matching
 * allow rule). Call this immediately before EVERY network action.
 */
export function assertInScope(roe: ValidatedRoe, url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new RoeViolationError(`malformed URL "${url}"`, url);
  }

  const scheme = parsed.protocol.replace(':', '');
  if (scheme !== 'http' && scheme !== 'https') {
    throw new RoeViolationError(`scheme "${scheme}" is never in scope`, url);
  }
  const host = normalizeHost(parsed.hostname);

  for (const denied of roe.deniedHosts ?? []) {
    const d = normalizeHost(denied);
    if (host === d || host.endsWith(`.${d}`)) {
      throw new RoeViolationError(`host "${host}" is on the RoE deny-list`, url);
    }
  }

  const port = parsed.port === '' ? DEFAULT_PORT[scheme] : Number.parseInt(parsed.port, 10);
  const path = parsed.pathname || '/';

  const matched = roe.allowedHosts.some(
    (rule) =>
      hostMatches(rule, host) &&
      schemeAllowed(rule, scheme) &&
      portAllowed(rule, scheme, port) &&
      pathAllowed(rule, path),
  );

  if (!matched) {
    throw new RoeViolationError(`"${host}${path}" (${scheme}:${port}) is out of scope`, url);
  }
}

/** Non-throwing scope predicate for callers that prefer a boolean. */
export function isInScope(roe: ValidatedRoe, url: string): boolean {
  try {
    assertInScope(roe, url);
    return true;
  } catch {
    return false;
  }
}
