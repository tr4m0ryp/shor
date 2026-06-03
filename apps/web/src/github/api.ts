/**
 * GitHub REST API calls authenticated with a user's Personal Access Token (PAT).
 *
 * All requests use the global `fetch` with a Bearer PAT, the `github+json`
 * Accept header, and a `User-Agent` (required by api.github.com). Two surfaces:
 *   - `getGithubUser` — `GET /user`; also the token-validation probe on connect.
 *   - `listUserRepos` — owned (incl. private) + collaborator/org + forked repos,
 *     merged with the caller's starred repos, de-duped by `full_name`.
 *
 * Per-call errors are tolerated: a failing page returns what has been collected
 * so far rather than throwing, so a partial GitHub outage still yields a usable
 * list. `getGithubUser` is the exception — it surfaces auth failures so the
 * connect flow can reject an invalid token.
 */

const GITHUB_API = 'https://api.github.com';

/** Standard headers for every PAT-authenticated GitHub API call. */
function githubHeaders(pat: string): Record<string, string> {
  return {
    Authorization: `Bearer ${pat}`,
    Accept: 'application/vnd.github+json',
    'User-Agent': 'shor',
    'X-GitHub-Api-Version': '2022-11-28',
  };
}

/** The authenticated GitHub user. */
export interface GithubUser {
  readonly login: string;
}

/**
 * Resolve the authenticated user for `pat` (`GET /user`). Throws on a non-2xx
 * response — used both to surface the login and to VALIDATE a token on connect.
 */
export async function getGithubUser(pat: string): Promise<GithubUser> {
  const res = await fetch(`${GITHUB_API}/user`, { headers: githubHeaders(pat) });
  if (!res.ok) {
    throw new Error(`github GET /user failed: ${res.status} ${res.statusText}`);
  }
  const body = (await res.json()) as { login?: unknown };
  if (typeof body.login !== 'string') {
    throw new Error('github GET /user returned no login');
  }
  return { login: body.login };
}

/** One repository the caller can select for a white-box scan. */
export interface GithubRepo {
  readonly fullName: string;
  readonly private: boolean;
  readonly fork: boolean;
  readonly stargazed: boolean;
  readonly defaultBranch: string;
  readonly cloneUrl: string;
}

/** Raw repo shape from the GitHub REST API (only the fields we consume). */
interface RawRepo {
  full_name?: unknown;
  private?: unknown;
  fork?: unknown;
  default_branch?: unknown;
  clone_url?: unknown;
}

function toRepo(raw: RawRepo, stargazed: boolean): GithubRepo | null {
  if (typeof raw.full_name !== 'string' || typeof raw.clone_url !== 'string') return null;
  return {
    fullName: raw.full_name,
    private: raw.private === true,
    fork: raw.fork === true,
    stargazed,
    defaultBranch: typeof raw.default_branch === 'string' ? raw.default_branch : 'main',
    cloneUrl: raw.clone_url,
  };
}

/** Fetch one page of an array endpoint; returns [] on any error (tolerant). */
async function fetchRepoPage(pat: string, path: string): Promise<RawRepo[]> {
  try {
    const res = await fetch(`${GITHUB_API}${path}`, { headers: githubHeaders(pat) });
    if (!res.ok) return [];
    const body = await res.json();
    return Array.isArray(body) ? (body as RawRepo[]) : [];
  } catch {
    return [];
  }
}

/**
 * List the caller's selectable repos for `pat`, de-duped by `full_name`:
 *   - owned (incl. private), collaborator, and org-member repos — up to 5 pages
 *     of `GET /user/repos` (100/page, sorted by recent activity);
 *   - starred repos — up to 2 pages of `GET /user/starred` (marked `stargazed`).
 * An owned repo that is also starred keeps its owned entry (first write wins);
 * starred-only repos are added with `stargazed: true`.
 *
 * Tolerant: a failing page contributes nothing rather than aborting the list.
 */
export async function listUserRepos(pat: string): Promise<GithubRepo[]> {
  const byFullName = new Map<string, GithubRepo>();

  // Owned / collaborator / org-member repos (default-branch + fork flags here).
  for (let page = 1; page <= 5; page++) {
    const raw = await fetchRepoPage(
      pat,
      `/user/repos?per_page=100&affiliation=owner,collaborator,organization_member&sort=updated&page=${page}`,
    );
    for (const r of raw) {
      const repo = toRepo(r, false);
      if (repo && !byFullName.has(repo.fullName)) byFullName.set(repo.fullName, repo);
    }
    if (raw.length < 100) break;
  }

  // Starred repos — added only if not already present (mark starred-only ones).
  for (let page = 1; page <= 2; page++) {
    const raw = await fetchRepoPage(pat, `/user/starred?per_page=100&page=${page}`);
    for (const r of raw) {
      const repo = toRepo(r, true);
      if (repo && !byFullName.has(repo.fullName)) byFullName.set(repo.fullName, repo);
    }
    if (raw.length < 100) break;
  }

  return [...byFullName.values()];
}
