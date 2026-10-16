from __future__ import annotations

from typing import Any

def _csv(values: list[Any] | None) -> str:
    if not values:
        return "—"
    return ", ".join(str(item) for item in values)


def _history(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "—"
    parts: list[str] = []
    for item in rows:
        groups = ", ".join(item.get("group_ids") or [])
        parts.append(f"{item.get('date', '')} {item.get('role_id', '')} [{groups}]".strip())
    return "; ".join(parts)


def _temporary(grants: list[dict[str, Any]]) -> str:
    if not grants:
        return "—"
    parts: list[str] = []
    for grant in grants:
        state = "expired" if grant.get("expired") else "active"
        until = grant.get("expires_on") or "open"
        parts.append(f"{grant.get('permission_id', '')} until {until} ({state})")
    return "; ".join(parts)


def _catalog(state: dict) -> dict[str, Any]:
    """Lean rows for every stored collection. The identity screen stays capped."""
    world = state["world"]
    analysis = state["analysis"]
    resources = {row["id"]: row for row in world["resources"]}
    people: list[dict[str, Any]] = []
    kind_counts = {"employee": 0, "contractor": 0, "service": 0}
    dept_people: dict[str, int] = {}
    for row in world["identities"]:
        scored = analysis["identities"][row["id"]]
        kind = str(row["kind"])
        if kind in kind_counts:
            kind_counts[kind] += 1
        dept_people[row["department"]] = dept_people.get(row["department"], 0) + 1
        people.append(
            {
                "id": row["id"],
                "name": row["name"],
                "kind": kind,
                "status": row["status"],
                "department": row["department"],
                "team": row["team"],
                "role_id": row["role_id"],
                "role_title": scored["role_title"],
                "responsibility": row["responsibility"],
                "projects": _csv(row["projects"]),
                "groups": _csv(row["group_ids"]),
                "direct_roles": _csv(row["direct_role_ids"]),
                "extra_grants": _csv(row["extra_permission_ids"]),
                "denies": _csv(row["deny_permission_ids"]),
                "temporary": _temporary(row["temporary_grants"]),
                "role_history": _history(row["role_history"]),
                "scenarios": _csv(row["scenarios"]),
                "split": row["split"],
                "showcase": row["showcase"] or "—",
                "drift": scored["drift"]["drift"],
                "grants": scored["drift"]["granted"],
                "needed": scored["drift"]["needed"],
                "anomaly": scored["anomaly"],
            }
        )
    people.sort(key=lambda item: item["id"])
    dept_resources: dict[str, int] = {}
    for row in world["resources"]:
        dept_resources[row["department"]] = dept_resources.get(row["department"], 0) + 1
    departments = [
        {
            "id": row["id"],
            "name": row["name"],
            "people": dept_people.get(row["id"], 0),
            "resources": dept_resources.get(row["id"], 0),
        }
        for row in world["departments"]
    ]
    roles = [
        {
            "id": row["id"],
            "title": row["title"],
            "department": row["department"],
            "job_role": "yes" if row["job_role"] else "no",
            "duty": row["duty"],
            "grant_count": len(row["grant_permission_ids"]),
            "grants": _csv(row["grant_permission_ids"]),
        }
        for row in world["roles"]
    ]
    groups = [
        {
            "id": row["id"],
            "name": row["name"],
            "purpose": row["purpose"],
            "department": row["department"],
            "roles": _csv(row["role_ids"]),
        }
        for row in world["groups"]
    ]
    resource_rows = [
        {
            "id": row["id"],
            "name": row["name"],
            "kind": row["kind"],
            "sensitivity": row["sensitivity"],
            "environment": row["environment"],
            "department": row["department"],
        }
        for row in world["resources"]
    ]
    permissions = []
    for row in world["permissions"]:
        resource = resources[row["resource_id"]]
        permissions.append(
            {
                "id": row["id"],
                "action": row["action"],
                "resource_id": row["resource_id"],
                "resource": resource["name"],
                "department": resource["department"],
                "sensitivity": resource["sensitivity"],
                "privileged": "yes" if row["privileged"] else "no",
                "requirement_class": row["requirement_class"],
            }
        )
    workflows = [
        {
            "id": row["id"],
            "name": row["name"],
            "cadence": row["cadence"],
            "roles": _csv(row["role_ids"]),
            "permissions": _csv(row["required_permission_ids"]),
        }
        for row in world["workflows"]
    ]
    labels = [
        {
            "identity_id": row["identity_id"],
            "permission_id": row["permission_id"],
            "scenario": row["scenario"],
            "expected": row["expected"],
            "y_unjustified": row["y_unjustified"],
            "y_legitimate": row["y_legitimate"],
        }
        for row in world["labels"]
    ]
    exceptions = [
        {
            "identity_id": row["identity_id"],
            "permission_id": row["permission_id"],
            "active": "yes" if row["active"] else "no",
            "expires_on": row["expires_on"] or "—",
            "reason": row["reason"],
        }
        for row in world["exceptions"]
    ]
    findings = [
        {
            "identity_id": row["identity_id"],
            "name": row["name"],
            "role_title": row["role_title"],
            "permission_id": row["permission_id"],
            "action": row["action"],
            "resource_name": row["resource_name"],
            "outcome": row["outcome"],
            "severity": row["severity"],
            "necessity": row["necessity"],
            "scenario": row["scenario"],
        }
        for row in analysis["findings"]
    ]
    approvals = state["store"].legacy()
    job_roles = sum(1 for row in world["roles"] if row["job_role"])
    return {
        "counts": {
            "people": len(people),
            "employees": kind_counts["employee"],
            "contractors": kind_counts["contractor"],
            "service_accounts": kind_counts["service"],
            "departments": len(departments),
            "roles": len(roles),
            "job_roles": job_roles,
            "groups": len(groups),
            "resources": len(resource_rows),
            "permissions": len(permissions),
            "workflows": len(workflows),
            "labels": len(labels),
            "exceptions": len(exceptions),
            "usage": len(world["usage"]),
            "activity": len(world["activity"]),
            "findings": len(findings),
            "approvals": len(approvals),
        },
        "people": people,
        "departments": departments,
        "roles": roles,
        "groups": groups,
        "resources": resource_rows,
        "permissions": permissions,
        "workflows": workflows,
        "labels": labels,
        "exceptions": exceptions,
        "usage": world["usage"],
        "activity": world["activity"],
        "findings": findings,
        "approvals": approvals,
    }


