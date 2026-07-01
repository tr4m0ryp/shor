"""Pluggable auth for the Shor MCP connector (mirrors enrichment-mcp's auth.py).

``build_auth`` selects the auth provider from config so the rest of the server
never branches on it. Modes, by ``MCP_OAUTH_PROVIDER``:

- ``"workos"`` — OAuth via WorkOS AuthKit using FastMCP's full ``WorkOSProvider``
  OAuth proxy: FastMCP performs Dynamic Client Registration for the claude.ai
  connector itself and proxies the actual login to AuthKit with a single
  pre-registered WorkOS client. This does NOT depend on AuthKit advertising a
  registration endpoint (it does not), which is exactly why the proxy is used.
  Needs ``WORKOS_AUTHKIT_DOMAIN`` + ``WORKOS_CLIENT_ID`` + ``WORKOS_CLIENT_SECRET``
  + ``MCP_BASE_URL``; register ``<MCP_BASE_URL>/auth/callback`` on the WorkOS app.
- empty — static bearer (Claude Code) when ``MCP_BEARER_TOKEN`` is set, else
  authless (local dev only).
"""

from __future__ import annotations

import logging

from fastmcp.server.auth import AuthProvider
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

from .config import Config

logger = logging.getLogger(__name__)

# Identity attached to the static bearer token (cosmetic; OAuth fills real ids).
_BEARER_CLIENT_ID = "shor-connector-session"


def build_auth(config: Config) -> AuthProvider | None:
    """Return the server's single auth layer, or ``None`` for authless dev."""
    provider = config.mcp_oauth_provider
    if provider == "workos":
        return _workos(config)
    if provider:
        raise ValueError(
            f"Unknown MCP_OAUTH_PROVIDER={provider!r}; use 'workos' or leave empty for bearer.",
        )

    if config.mcp_bearer_token:
        return StaticTokenVerifier(
            tokens={config.mcp_bearer_token: {"client_id": _BEARER_CLIENT_ID, "scopes": []}},
        )
    logger.warning(
        "No auth configured (no MCP_OAUTH_PROVIDER, no MCP_BEARER_TOKEN) — starting AUTHLESS: "
        "every /mcp request is accepted. Configure auth before exposing this server.",
    )
    return None


def _require(config: Config, *fields: str) -> None:
    missing = [f for f in fields if not getattr(config, f, "")]
    if missing:
        env = {
            "workos_authkit_domain": "WORKOS_AUTHKIT_DOMAIN",
            "workos_client_id": "WORKOS_CLIENT_ID",
            "workos_client_secret": "WORKOS_CLIENT_SECRET",
            "mcp_base_url": "MCP_BASE_URL",
        }
        names = ", ".join(env.get(f, f) for f in missing)
        raise ValueError(f"MCP_OAUTH_PROVIDER={config.mcp_oauth_provider!r} requires: {names}")


def _workos(config: Config) -> AuthProvider:
    """OAuth via WorkOS AuthKit using the full ``WorkOSProvider`` (OAuth proxy)."""
    from fastmcp.server.auth.providers.workos import WorkOSProvider

    _require(config, "workos_authkit_domain", "workos_client_id", "workos_client_secret", "mcp_base_url")
    logger.info(
        "Auth: WorkOS OAuth proxy (domain=%s, resource=%s)",
        config.workos_authkit_domain,
        config.mcp_base_url,
    )
    return WorkOSProvider(
        client_id=config.workos_client_id,
        client_secret=config.workos_client_secret,
        authkit_domain=config.workos_authkit_domain,
        base_url=config.mcp_base_url,
    )


__all__ = ["build_auth"]
