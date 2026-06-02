/**
 * Git URL validation — installation-scoped allowlist (ADR-041).
 *
 * This REPLACES storron's open `isGitUrl`, which accepted any github.com /
 * gitlab.com / `*.git` URL and fed it straight to `git clone` — a server-side
 * request forgery (SSRF) surface (an attacker-controlled "repo URL" could point
 * `git` at internal hosts). Here a URL is valid ONLY when it is an HTTPS GitHub
 * repo whose `owner/name` is present in the App-installation allowlist. There is
 * no arbitrary-host clone path.
 */

import type { InstallationRepo } from './github-app.js';

/** Parsed `owner/name` from a GitHub HTTPS repo URL. */
export interface RepoSlug {
  readonly owner: string;
  readonly name: string;
  /** `owner/name`. */
  readonly fullName: string;
}

/**
 * Structurally validate a GitHub HTTPS clone URL and extract `owner/name`.
 *
 * Tightened vs storron: HTTPS + host exactly `github.com` only (no `git@`, no
 * `http://`, no gitlab, no bare `*.git` on arbitrary hosts). Returns `null` for
 * anything that is not a well-formed GitHub repo URL. Structural validity does
 * NOT authorize a clone — `assertInstallationRepo` is the authorization gate.
 */
export function parseGithubRepoUrl(url: string): RepoSlug | null {
  if (typeof url !== 'string' || url.length === 0) return null;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:') return null;
  if (parsed.hostname !== 'github.com') return null;
  // Reject embedded credentials / non-default ports — both are SSRF smells.
  if (parsed.username || parsed.password || parsed.port) return null;

  const segments = parsed.pathname.split('/').filter(Boolean);
  if (segments.length < 2) return null;
  const owner = segments[0] as string;
  const name = (segments[1] as string).replace(/\.git$/, '');
  if (!isSlugPart(owner) || !isSlugPart(name)) return null;

  return { owner, name, fullName: `${owner}/${name}` };
}

/**
 * Installation-scoped replacement for storron's `isGitUrl`.
 *
 * A URL is a valid clone target ONLY if it is a structurally valid GitHub repo
 * URL AND its `owner/name` appears in the supplied installation allowlist. Any
 * arbitrary host fails closed.
 */
export function isInstallationGitUrl(url: string, allowlist: readonly InstallationRepo[]): boolean {
  const slug = parseGithubRepoUrl(url);
  if (!slug) return false;
  const target = slug.fullName.toLowerCase();
  return allowlist.some((r) => r.fullName.toLowerCase() === target);
}

/**
 * Authorize a clone: return the allowlisted `InstallationRepo` for `fullName`,
 * or throw. This is the single gate every clone must pass through (ADR-041);
 * there is deliberately no bypass that accepts a raw URL.
 */
export function assertInstallationRepo(
  fullName: string,
  allowlist: readonly InstallationRepo[],
): InstallationRepo {
  const target = fullName.toLowerCase();
  const repo = allowlist.find((r) => r.fullName.toLowerCase() === target);
  if (!repo) {
    throw new Error(`Repo "${fullName}" is not in the GitHub App installation allowlist; refusing to clone`);
  }
  return repo;
}

/** GitHub owner/repo names: letters, digits, `-`, `_`, `.` (no path traversal). */
function isSlugPart(part: string): boolean {
  return /^[A-Za-z0-9._-]+$/.test(part) && part !== '.' && part !== '..';
}
