"""Counterfactual access changes on a copy of the policy state."""
from __future__ import annotations

from entitleguard.policy import Directory


def _critical(directory: Directory, permission_ids: set[str]) -> list[str]:
    names = []
    for permission_id in sorted(permission_ids):
        permission = directory.permissions[permission_id]
        resource = directory.resources[permission["resource_id"]]
        if resource["sensitivity"] in {"high", "critical"}:
            names.append(resource["name"])
    return names


def simulate(directory: Directory, identity_id: str, change: dict) -> dict:
    """Apply one change and compare reachability and workflows.

    Missing usage does not count as proof that removal is safe.
    """
    identity = directory.identity(identity_id)
    before, _sources = directory.effective(identity)
    drop_groups: set[str] = set()
    drop_permissions: set[str] = set()
    drop_expired = False
    drop_roles: set[str] = set()
    drop_direct: set[str] = set()
    kind = change.get("type")
    if kind == "remove_group":
        if change.get("group_id") not in identity["group_ids"]:
            raise ValueError("Group is not assigned to this identity")
        drop_groups.add(str(change["group_id"]))
    elif kind == "remove_permission":
        if change.get("permission_id") not in before:
            raise ValueError("Permission is not effective for this identity")
        drop_permissions.add(str(change["permission_id"]))
    elif kind == "remove_direct_role":
        if change.get("role_id") not in identity["direct_role_ids"]:
            raise ValueError("Direct role is not assigned to this identity")
        drop_roles.add(change["role_id"])
    elif kind == "remove_direct_grant":
        if change.get("permission_id") not in identity["extra_permission_ids"]:
            raise ValueError("Direct grant is not assigned to this identity")
        drop_direct.add(change["permission_id"])
    elif kind in {"narrow", "make_temporary"}:
        raise ValueError(f"{kind} would keep a grant. This simulator only removes access.")
    elif kind == "revoke_expired_temporary":
        drop_expired = True
    else:
        raise ValueError(f"unsupported change {kind}")

    after, _after_sources = directory.effective(
        identity,
        drop_groups=drop_groups,
        drop_roles=drop_roles,
        drop_direct=drop_direct,
        drop_permissions=drop_permissions,
        drop_expired_temporary=drop_expired,
    )
    removed = before - after
    workflows = []
    for workflow in directory.workflows_for(identity):
        required = set(workflow["required_permission_ids"])
        before_ok = required <= before
        after_ok = required <= after
        workflows.append(
            {
                "id": workflow["id"],
                "name": workflow["name"],
                "cadence": workflow["cadence"],
                "before": "allowed" if before_ok else "unavailable",
                "after": "allowed" if after_ok else "broken" if before_ok else "unavailable",
            }
        )
    broken = [row["name"] for row in workflows if row["after"] == "broken"]
    needed = directory.needs(identity)
    drops_documented = bool(removed & needed)
    missing_usage = any(directory.usage_for(identity_id, permission_id) is None for permission_id in removed)
    unclassified = any(
        directory.permissions[permission_id]["requirement_class"] == "unclassified"
        for permission_id in removed
    )
    safe = bool(removed) and not broken and not drops_documented and not missing_usage and not unclassified
    reason = "Verified safe against documented workflows."
    if not removed:
        reason = "The change does not remove any effective permission."
        safe = False
    elif broken:
        reason = "A documented workflow would break."
    elif drops_documented:
        reason = "The change removes a documented business need."
    elif missing_usage:
        reason = "No activity log exists, so non-use cannot show the change is safe."
    elif unclassified:
        reason = "The requirement is unclassified and stays a review."
    return {
        "change": change,
        "before_permission_ids": sorted(before),
        "retained_permission_ids": sorted(after),
        "sources_before": _sources,
        "sources_after": _after_sources,
        "verdict": "no_change" if not removed else "safe" if safe else "blocked",
        "scope": "all_sources" if kind == "remove_permission" else "specific_source",
        "removed_permission_ids": sorted(removed),
        "critical_before": _critical(directory, before),
        "critical_after": _critical(directory, after),
        "workflows": workflows,
        "broken_workflows": broken,
        "drops_documented_need": drops_documented,
        "missing_usage": missing_usage,
        "safe_to_remove": safe,
        "reason": reason,
    }
