"""The four Shor MCP tools. Each is a thin wrapper over ``/external/*``; none
re-implements scanning. The connector deliberately exposes NOTHING else — no
un-gated start, no white-box/repo tool, no delete/mutate-findings tool.

    start_blackbox_run  — the ONLY start path; structurally requires a launch token.
    list_active_runs    — read-only list of the tenant's in-flight scans.
    get_run_progress    — read-only status snapshot for one scan.
    get_share_url       — read-only guest link (the sole client-facing output).

A launch token can only be minted by the operator's approval backend, so a
routine holding these tools still cannot start an unauthorized scan.
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from . import shor_client


async def start_blackbox_run(
    engagement_id: str,
    authorization_token: str,
    roe: dict,
) -> dict[str, Any]:
    """Start a black-box security scan.

    REQUIRES a single-use ``authorization_token`` minted by a human approver for
    THIS engagement and THIS exact RoE; the run is rejected otherwise. The RoE is
    the signed DEFAULT-DENY allowlist the engine enforces on every network action.

    Args:
        engagement_id: The signed engagement this run belongs to.
        authorization_token: Single-use launch token from the human approval step.
            The routine cannot mint this — obtain it from the approver.
        roe: The signed DEFAULT-DENY Rules of Engagement, e.g.
            {"version": 1, "targetUrl": "https://app.example.com",
             "allowedHosts": [{"host": "app.example.com", "schemes": ["https"]}]}.

    Returns:
        {"projectId": ..., "scanId": ..., "status": ...}
    """
    r = await shor_client.launch(engagement_id, authorization_token, roe)
    return {"projectId": r.get("projectId"), "scanId": r.get("scanId"), "status": r.get("status")}


async def list_active_runs() -> dict[str, Any]:
    """List the in-flight scans (status running or pending), newest first.

    Read-only. Use it to see which runs are currently running.

    Returns:
        {"runs": [{"scanId", "projectId", "status", "progress", "startedAt"}, ...]}
    """
    return {"runs": await shor_client.list_active_runs()}


async def get_run_progress(scan_id: str) -> dict[str, Any]:
    """Read-only status of one scan.

    Args:
        scan_id: The scanId returned by start_blackbox_run.

    Returns:
        {"status", "progress", "findingCount", "startedAt", "finishedAt"}
    """
    r = await shor_client.get_scan(scan_id)
    return {
        "status": r.get("status"),
        "progress": r.get("progress"),
        "findingCount": r.get("findingCount"),
        "startedAt": r.get("startedAt"),
        "finishedAt": r.get("finishedAt"),
    }


async def get_share_url(project_id: str) -> dict[str, Any]:
    """Mint (or read) the project's read-only guest link — the only client-facing
    output of a run. Read-only with respect to scanning.

    Args:
        project_id: The projectId returned by start_blackbox_run.

    Returns:
        {"shareUrl": ...}
    """
    r = await shor_client.share(project_id)
    return {"shareUrl": r.get("shareUrl")}


def register_tools(mcp: FastMCP) -> None:
    """Register the four tools on ``mcp``."""
    mcp.tool(start_blackbox_run)
    mcp.tool(list_active_runs)
    mcp.tool(get_run_progress)
    mcp.tool(get_share_url)


__all__ = [
    "start_blackbox_run",
    "list_active_runs",
    "get_run_progress",
    "get_share_url",
    "register_tools",
]
