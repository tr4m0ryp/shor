"""FastMCP app, auth layer, tool registration, and ``run()``.

Builds the ``shor`` Streamable-HTTP server: one auth layer plus the four tools,
served at ``/mcp``. Construction is pure — importing this module (and the
module-level ``mcp`` app) opens no HTTP client; the Shor client connects lazily
on the first tool call. Auth is isolated in :mod:`.auth` (``build_auth``): a
static bearer for Claude Code, OR the WorkOS AuthKit OAuth proxy for the
claude.ai web connector. Selecting a mode is pure config; this module never
branches on it.
"""

from __future__ import annotations

import logging

from fastmcp import FastMCP

from .auth import build_auth
from .config import Config, get_config
from .tools import register_tools

logger = logging.getLogger(__name__)

SERVER_NAME = "shor"

INSTRUCTIONS = (
    "Shor black-box web-security scanning, exposed for authorized engagements only. "
    "A scan can be started ONLY with a single-use authorization token that a human "
    "approver mints for the specific engagement and the specific signed Rules of "
    "Engagement (RoE). You cannot mint that token; obtain it from the approval step and "
    "pass it verbatim to start_blackbox_run. The RoE you pass is the scope the engine "
    "enforces (default-deny). Share the read-only get_share_url link for results."
)


def build_server(config: Config | None = None) -> FastMCP:
    """Construct the FastMCP app with auth and the four registered tools. Pure."""
    config = config or get_config()
    mcp = FastMCP(SERVER_NAME, instructions=INSTRUCTIONS, auth=build_auth(config))
    register_tools(mcp)
    return mcp


# Module-level app object (registers tools + auth, opens no connections).
mcp = build_server()


def run() -> None:
    """Serve the app over Streamable HTTP at ``/mcp`` on the configured bind."""
    config = get_config()
    logger.info(
        "Starting %s over Streamable HTTP at http://%s:%d/mcp",
        SERVER_NAME,
        config.mcp_host,
        config.mcp_port,
    )
    mcp.run(transport="http", host=config.mcp_host, port=config.mcp_port)


__all__ = ["mcp", "run", "build_server"]
