// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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

import { randomUUID } from 'node:crypto';
import { getConfig } from '../../config.js';
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

// ---------------------------------------------------------------------------
// GitHub OAuth ("Connect with GitHub") web-login flow.
//
// A browser-redirect alternative to the PAT flow. `startGithubOauth` 302s to
// GitHub's authorize endpoint (CSRF-guarded by a short-lived `gh_oauth_state`
// cookie); `githubOauthCallback` re-gates the still-logged-in session, verifies
// the state, exchanges the `code` for a USER access token, validates it, and
// stores it in the SAME slot the PAT flow uses — so repo listing/cloning read it
// transparently. The browser is bounced back to `/?gh=connected|error`.
// ---------------------------------------------------------------------------

const STATE_COOKIE = 'gh_oauth_state';
/** Set the state cookie for `value` (short-lived, HttpOnly, SameSite=Lax). */
const stateCookie = (value: string): string => `${STATE_COOKIE}=${value}; Path=/; Max-Age=600; SameSite=Lax; HttpOnly`;
/** Clear the state cookie (Max-Age=0). */
const clearStateCookie = (): string => `${STATE_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly`;
/** A 302 browser redirect to `location`, optionally setting/clearing a cookie. */
const redirectTo = (location: string, setCookie?: string): ApiResponse => ({
  status: 302,
  body: {},
  redirect: location,
  ...(setCookie ? { setCookie } : {}),
});

/** Read the `gh_oauth_state` value from a raw `Cookie` request header (or null). */
function readStateCookie(cookieHeader: string | undefined): string | null {
  if (!cookieHeader) return null;
  for (const pair of cookieHeader.split(';')) {
    const eq = pair.indexOf('=');
    if (eq < 0) continue;
    if (pair.slice(0, eq).trim() === STATE_COOKIE) {
      return pair.slice(eq + 1).trim() || null;
    }
  }
  return null;
}

/**
 * `GET /settings/github/config` — report whether the OAuth flow is configured
 * (so the UI can show/hide the "Connect with GitHub" button). Gated like the
 * other settings routes for consistency.
 */
export async function getGithubConfig(cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  return ok({ oauthEnabled: getConfig().githubOauth.oauthEnabled });
}

/**
 * `GET /settings/github/start` — begin the OAuth dance. Mints a CSRF `state`,
 * stashes it in a short-lived cookie, and 302s to GitHub's authorize endpoint.
 * 400 when OAuth is not configured.
 */
export async function startGithubOauth(cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;

  const oauth = getConfig().githubOauth;
  if (!oauth.oauthEnabled) return badRequest('github oauth not configured');

  const state = randomUUID();
  const authorize =
    'https://github.com/login/oauth/authorize' +
    `?client_id=${encodeURIComponent(oauth.clientId)}` +
    `&redirect_uri=${encodeURIComponent(oauth.redirectUri)}` +
    '&scope=repo%20read:user' +
    `&state=${encodeURIComponent(state)}`;

  return redirectTo(authorize, stateCookie(state));
}

/**
 * `GET /settings/github/callback?code&state` — finish the OAuth dance. Re-gates
 * the session, verifies the `state` cookie, exchanges the code for a user access
 * token, validates + stores it, then 302s back to `/?gh=connected`. Any failure
 * (bad state, denied consent, exchange/validation error) bounces to `/?gh=error`
 * and clears the state cookie.
 */
export async function githubOauthCallback(
  query: { readonly code?: string | undefined; readonly state?: string | undefined; readonly error?: string | undefined },
  cookieHeader: string | undefined,
): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return redirectTo('/?gh=error', clearStateCookie());

  try {
    const expectedState = readStateCookie(cookieHeader);
    if (!expectedState || expectedState !== query.state) {
      return redirectTo('/?gh=error', clearStateCookie());
    }
    if (query.error || !query.code) {
      return redirectTo('/?gh=error', clearStateCookie());
    }

    const oauth = getConfig().githubOauth;
    if (!oauth.oauthEnabled) return redirectTo('/?gh=error', clearStateCookie());

    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: oauth.clientId,
        client_secret: oauth.clientSecret,
        code: query.code,
        redirect_uri: oauth.redirectUri,
      }),
    });
    const tokenBody = (await tokenRes.json()) as { access_token?: unknown };
    const accessToken = typeof tokenBody.access_token === 'string' ? tokenBody.access_token : '';
    if (!accessToken) return redirectTo('/?gh=error', clearStateCookie());

    // Validate the token, then store it in the same slot the PAT flow uses.
    await getGithubUser(accessToken);
    await storeGithubToken(g.tenantId, g.principal.uid, accessToken);

    return redirectTo('/?gh=connected', clearStateCookie());
  } catch {
    return redirectTo('/?gh=error', clearStateCookie());
  }
}
