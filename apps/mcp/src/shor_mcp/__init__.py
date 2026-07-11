"""Shor MCP connector — exposes Shor black-box scanning to Claude routines.

Thin FastMCP server wrapping Shor's ``/external/*`` control plane. One gated
start path (``start_blackbox_run``, requiring a human-minted single-use token the
connector can consume but never mint), one activity-reducing ``cancel_run``, and
read-only status/result/project tools. See :mod:`.tools` for the full set,
:mod:`.server` for the app, and :mod:`.auth` for the bearer / WorkOS-AuthKit auth
modes.
"""

from __future__ import annotations

from .server import build_server, mcp, run

__all__ = ["mcp", "run", "build_server"]
