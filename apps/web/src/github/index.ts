/**
 * Per-user GitHub integration — public surface.
 *
 * `token` stores/reads/deletes the caller's PAT (Secret Manager-backed). `api`
 * uses that PAT to resolve the authenticated user and list selectable repos
 * (owned incl. private + collaborator/org + forked + starred). White-box scans
 * clone a selected repo with the same PAT (see `ingest/git-source`).
 */

export { storeGithubToken, getGithubToken, deleteGithubToken } from './token.js';
export { type GithubUser, type GithubRepo, getGithubUser, listUserRepos } from './api.js';
