"""Project tools: list the tenant's projects and one project's scan history.

Read-only. The connector deliberately exposes no project create/update/delete
tool; these two only enumerate what already exists so the model can find a
project's id and review its past runs.
"""

from __future__ import annotations

from typing import Any

from .. import shor_client


async def list_projects() -> dict[str, Any]:
    """List the tenant's projects (targets).

    Read-only. Use it to find a projectId to pass to get_scan_history or
    get_share_url.

    Returns:
        {"projects": [ {project record}, ... ]}
    """
    return {"projects": await shor_client.list_projects()}


async def get_scan_history(project_id: str) -> dict[str, Any]:
    """List a project's scans, newest first.

    Read-only. The full run history for a project (unlike list_active_runs, which
    shows only in-flight runs across all projects).

    Args:
        project_id: The projectId returned by start_blackbox_run or list_projects.

    Returns:
        {"scans": [ {scan record}, ... ]}
    """
    return {"scans": await shor_client.get_scan_history(project_id)}


__all__ = ["list_projects", "get_scan_history"]
