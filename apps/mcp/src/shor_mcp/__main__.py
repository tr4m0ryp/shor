"""Entrypoint: ``python -m src.shor_mcp`` -> serve Streamable HTTP at ``/mcp``."""

from __future__ import annotations

from .server import run

if __name__ == "__main__":
    run()
