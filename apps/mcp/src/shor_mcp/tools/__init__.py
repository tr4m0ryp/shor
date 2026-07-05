"""The Shor MCP tools. Each is a thin wrapper over ``/external/*``; none
re-implements scanning. The connector exposes exactly one mutating start path
(``start_blackbox_run``, launch-token gated), one activity-reducing control
(``cancel_run``), and read-only status/result/project tools:

    start_blackbox_run  — the ONLY start path; structurally requires a launch token.
    cancel_run          — stop a running scan (operator kill switch); no token needed.
    list_active_runs    — read-only list of the tenant's in-flight scans.
    get_run_progress    — read-only status snapshot for one scan.
    get_findings        — read-only finding records for one scan.
    get_report          — read-only finalized executive report for one scan.
    get_attack_surface  — read-only attack-surface document for one scan.
    get_share_url       — read-only guest link (a client-facing output).
    list_projects       — read-only list of the tenant's projects.
    get_scan_history    — read-only list of one project's scans.

There is deliberately NO un-gated start, NO white-box/repo tool, and NO
delete/mutate-findings tool. A launch token can only be minted by the operator's
approval backend, so a routine holding these tools still cannot start an
unauthorized scan.
"""

from __future__ import annotations

from fastmcp import FastMCP

from .projects import get_scan_history, list_projects
from .results import get_attack_surface, get_findings, get_report, get_share_url
from .runs import cancel_run, get_run_progress, list_active_runs, start_blackbox_run

_TOOLS = (
    start_blackbox_run,
    cancel_run,
    list_active_runs,
    get_run_progress,
    get_findings,
    get_report,
    get_attack_surface,
    get_share_url,
    list_projects,
    get_scan_history,
)


def register_tools(mcp: FastMCP) -> None:
    """Register every Shor tool on ``mcp``."""
    for tool in _TOOLS:
        mcp.tool(tool)


__all__ = [
    "start_blackbox_run",
    "cancel_run",
    "list_active_runs",
    "get_run_progress",
    "get_findings",
    "get_report",
    "get_attack_surface",
    "get_share_url",
    "list_projects",
    "get_scan_history",
    "register_tools",
]
