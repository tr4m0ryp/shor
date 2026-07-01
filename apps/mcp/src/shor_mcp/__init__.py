"""Shor MCP connector — exposes Shor black-box scanning to Claude routines.

Thin FastMCP server wrapping Shor's ``/external/*`` control plane. Four tools;
launch is gated by a human-minted, single-use authorization token the connector
can consume but never mint. See :mod:`.server` for the app and :mod:`.auth` for
the bearer / WorkOS-AuthKit auth modes.
"""

from __future__ import annotations

from .server import build_server, mcp, run

__all__ = ["mcp", "run", "build_server"]
