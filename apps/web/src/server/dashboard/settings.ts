/**
 * Dashboard GitHub-settings + repo-listing API.
 *
 * Replaces the App-installation + zip flow with a per-user GitHub PAT (stored in
 * Secret Manager) used to list and clone repos:
 *
 *   GET    /settings/github  → { connected, login? }   token presence + identity
 *   POST   /settings/github  → { connected:true, login } validate + store a PAT
 *   DELETE /settings/github  → { connected:false }       remove the PAT
 *   GET    /github/repos     → { repos:[...] }           selectable repos
 *
 * Every handler is authenticated and tenant+user-scoped via `gate()`; the PAT is
 * keyed on the principal's `(tenantId, uid)`.
 */

import { deleteGithubToken, getGithubToken, getGithubUser, listUserRepos, storeGithubToken } from '../../github/index.js';
import type { ApiResponse } from '../router.js';
import { badRequest, gate, notFound, ok, serverError } from './auth-util.js';

/**
 * `GET /settings/github` — report whether the caller has a working GitHub PAT.
 * Returns `{ connected:false }` when no token is stored OR the stored token no
 * longer authenticates (revoked/expired); `{ connected:true, login }` otherwise.
 */
export async function getGithubSettings(cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const pat = await getGithubToken(g.tenantId, g.principal.uid);
    if (!pat) return ok({ connected: false });
    try {
      const user = await getGithubUser(pat);
      return ok({ connected: true, login: user.login });
    } catch {
      // A stored-but-invalid token reads as not connected (prompt re-connect).
      return ok({ connected: false });
    }
  } catch (err) {
    return serverError(err);
  }
}

/**
 * `POST /settings/github` — validate `{ token }` via `GET /user`, then store it.
 * Returns 400 when the token is missing or does not authenticate.
 */
export async function connectGithub(
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;

  const token = typeof body.token === 'string' ? body.token.trim() : '';
  if (!token) return badRequest('token is required');

  let login: string;
  try {
    login = (await getGithubUser(token)).login;
  } catch {
    return badRequest('invalid github token');
  }

  try {
    await storeGithubToken(g.tenantId, g.principal.uid, token);
    return ok({ connected: true, login });
  } catch (err) {
    return serverError(err);
  }
}

/** `DELETE /settings/github` — remove the caller's stored PAT. */
export async function disconnectGithub(cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    await deleteGithubToken(g.tenantId, g.principal.uid);
    return ok({ connected: false });
  } catch (err) {
    return serverError(err);
  }
}

/**
 * `GET /github/repos` — list the caller's selectable repos using the stored PAT.
 * 404 `{ error:'github not connected' }` when no token is configured.
 */
export async function listGithubRepos(cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const pat = await getGithubToken(g.tenantId, g.principal.uid);
    if (!pat) return notFound('github not connected');
    const repos = await listUserRepos(pat);
    return ok({ repos });
  } catch (err) {
    return serverError(err);
  }
}
