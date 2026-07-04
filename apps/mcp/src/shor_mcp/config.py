"""Typed configuration for the Shor MCP connector.

Plain ``@dataclass`` + ``python-dotenv`` (mirrors the enrichment-mcp pattern).
The connector is a thin, DB-less, mint-secret-less translator over Shor's
``/external/*`` control plane. It holds exactly two secrets: the engine trigger
token it presents to ``/external/*`` (server-to-server), and — in bearer mode —
the token Claude Code presents to it. It NEVER holds ``SHOR_LAUNCH_MINT_TOKEN``,
so by construction it cannot mint launch tokens.

Auth modes (``MCP_OAUTH_PROVIDER``):
  - empty   -> static bearer (Claude Code) via ``MCP_BEARER_TOKEN``.
  - authkit -> STATELESS OAuth via WorkOS AuthKit: the connector only verifies
    AuthKit JWTs; claude.ai registers (DCR) and refreshes directly with AuthKit,
    so restarts never force re-authentication. Needs ``WORKOS_AUTHKIT_DOMAIN`` +
    ``MCP_BASE_URL`` and DCR enabled in the WorkOS dashboard.
  - workos  -> OAuth via WorkOS AuthKit using FastMCP's ``WorkOSProvider`` proxy
    (STATEFUL — avoid on ephemeral hosts). Needs ``WORKOS_AUTHKIT_DOMAIN`` +
    ``WORKOS_CLIENT_ID`` + ``WORKOS_CLIENT_SECRET`` + ``MCP_BASE_URL``;
    ``<MCP_BASE_URL>/auth/callback`` must be an allowed WorkOS redirect URI.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    # Shor control plane whose /external/* this wraps, and the bearer for it.
    shor_base_url: str = "http://localhost:3457"
    engine_trigger_token: str = ""

    # MCP transport bind + static bearer (bearer mode).
    mcp_bearer_token: str = ""
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8080

    # Auth mode. Empty -> static bearer / authless. "authkit" -> stateless
    # AuthKit resource server (recommended). "workos" -> stateful OAuth proxy.
    mcp_oauth_provider: str = ""
    # Public HTTPS base URL of THIS connector (no /mcp) — what OAuth metadata
    # advertises and what the claude.ai connector URL resolves to.
    mcp_base_url: str = ""
    # WorkOS AuthKit domain + the one pre-registered application client.
    workos_authkit_domain: str = ""
    workos_client_id: str = ""
    workos_client_secret: str = ""


def _load_config() -> Config:
    cfg = Config(
        shor_base_url=os.environ.get("SHOR_BASE_URL", "http://localhost:3457").strip().rstrip("/"),
        engine_trigger_token=os.environ.get("SHOR_ENGINE_TRIGGER_TOKEN", "").strip(),
        mcp_bearer_token=os.environ.get("MCP_BEARER_TOKEN", "").strip(),
        mcp_host=os.environ.get("MCP_HOST", "0.0.0.0").strip(),
        # Cloud Run injects PORT; honor it first, then MCP_PORT, then default.
        mcp_port=int(os.environ.get("PORT") or os.environ.get("MCP_PORT") or "8080"),
        mcp_oauth_provider=os.environ.get("MCP_OAUTH_PROVIDER", "").strip().lower(),
        mcp_base_url=os.environ.get("MCP_BASE_URL", "").strip().rstrip("/"),
        workos_authkit_domain=os.environ.get("WORKOS_AUTHKIT_DOMAIN", "").strip().rstrip("/"),
        workos_client_id=os.environ.get("WORKOS_CLIENT_ID", "").strip(),
        workos_client_secret=os.environ.get("WORKOS_CLIENT_SECRET", "").strip(),
    )

    if not cfg.engine_trigger_token:
        logging.getLogger(__name__).error(
            "Missing SHOR_ENGINE_TRIGGER_TOKEN — the connector cannot call /external/*.",
        )

    return cfg


_config: Config | None = None


def get_config() -> Config:
    """Return the process-wide ``Config``, building it on first call."""
    global _config
    if _config is None:
        _config = _load_config()
    return _config
