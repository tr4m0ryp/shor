"""Pluggable auth for the Shor MCP connector (mirrors enrichment-mcp's auth.py).

``build_auth`` selects the auth provider from config so the rest of the server
never branches on it. Modes, by ``MCP_OAUTH_PROVIDER``:

- ``"authkit"`` — STATELESS OAuth via WorkOS AuthKit: the server is a pure
  RFC 9728 resource server that verifies AuthKit-issued JWTs against the tenant
  JWKS. claude.ai performs Dynamic Client Registration and token refresh
  directly with AuthKit (the tenant DOES advertise a registration endpoint —
  DCR is enabled in the WorkOS dashboard), so no OAuth state lives in this
  process and Cloud Run instance recycling never forces re-authentication.
  Needs only ``WORKOS_AUTHKIT_DOMAIN`` + ``MCP_BASE_URL``.
- ``"workos"`` — OAuth via WorkOS AuthKit using FastMCP's full ``WorkOSProvider``
  OAuth proxy: FastMCP performs DCR for the claude.ai connector itself and
  proxies the actual login to AuthKit with a single pre-registered WorkOS
  client. STATEFUL: client registrations and token mappings die with the
  instance — prefer ``authkit`` on ephemeral hosts.
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
    if provider == "authkit":
        return _authkit(config)
    if provider == "workos":
        return _workos(config)
    if provider:
        raise ValueError(
            f"Unknown MCP_OAUTH_PROVIDER={provider!r}; use 'authkit', 'workos', "
            "or leave empty for bearer.",
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


def _authkit(config: Config) -> AuthProvider:
    """Stateless OAuth via WorkOS AuthKit (``AuthKitProvider``).

    Pure RFC 9728 resource server: verifies AuthKit JWTs via JWKS and points
    clients at AuthKit for DCR + refresh. No OAuth state in this process, so
    connections survive restarts. Requires DCR enabled in the WorkOS dashboard.
    """
    from fastmcp.server.auth.providers.jwt import JWTVerifier
    from fastmcp.server.auth.providers.workos import AuthKitProvider

    _require(config, "workos_authkit_domain", "mcp_base_url")
    logger.info(
        "Auth: AuthKit stateless resource server (domain=%s, resource=%s)",
        config.workos_authkit_domain,
        config.mcp_base_url,
    )
    domain = config.workos_authkit_domain.rstrip("/")
    # Explicit verifier = issuer + signature only, no audience binding. The
    # default verifier binds aud to the resource URL, which additionally
    # requires that URL be configured as a Resource Indicator in the WorkOS
    # dashboard; gmail-mcp-server runs without the aud check and stays
    # connected, so mirror that proven setup.
    return AuthKitProvider(
        authkit_domain=domain,
        base_url=config.mcp_base_url,
        token_verifier=JWTVerifier(
            jwks_uri=f"{domain}/oauth2/jwks",
            issuer=domain,
            algorithm="RS256",
        ),
    )


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
