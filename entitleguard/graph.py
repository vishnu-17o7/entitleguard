"""Access graph. Paths are structural. Effective permission is decided elsewhere."""
from __future__ import annotations

import networkx as nx

from entitleguard.policy import Directory


def build_ego(directory: Directory, identity: dict) -> nx.DiGraph:
    """Directed graph of groups, roles, and resources this identity can reach."""
    graph = nx.MultiDiGraph()
    graph.add_node(identity["id"], kind="identity", label=identity["name"])
    granted, _sources = directory.effective(identity)

    def link_role(source: str, role_id: str) -> None:
        role = directory.roles[role_id]
        graph.add_node(role_id, kind="role", label=role["title"])
        graph.add_edge(source, role_id, relation="assigns")
        for permission_id in role["grant_permission_ids"]:
            permission = directory.permissions.get(permission_id)
            if permission is None:
                continue
            resource = directory.resources[permission["resource_id"]]
            graph.add_node(
                resource["id"],
                kind="resource",
                label=resource["name"],
                sensitivity=resource["sensitivity"],
            )
            graph.add_edge(
                role_id,
                resource["id"],
                relation="grants",
                permission_id=permission_id,
                action=permission["action"],
                effective=permission_id in granted,
            )

    for group_id in identity["group_ids"]:
        group = directory.groups[group_id]
        graph.add_node(group_id, kind="group", label=group["name"], purpose=group["purpose"])
        graph.add_edge(identity["id"], group_id, relation="member")
        for role_id in group["role_ids"]:
            link_role(group_id, role_id)
    for role_id in identity["direct_role_ids"]:
        link_role(identity["id"], role_id)
    for permission_id in identity["extra_permission_ids"]:
        permission = directory.permissions.get(permission_id)
        if permission is None:
            continue
        resource = directory.resources[permission["resource_id"]]
        graph.add_node(resource["id"], kind="resource", label=resource["name"], sensitivity=resource["sensitivity"])
        graph.add_edge(
            identity["id"],
            resource["id"],
            relation="direct",
            permission_id=permission_id,
            action=permission["action"],
            effective=permission_id in granted,
        )
    for grant in identity["temporary_grants"]:
        permission = directory.permissions.get(grant["permission_id"])
        if permission is None:
            continue
        resource = directory.resources[permission["resource_id"]]
        graph.add_node(resource["id"], kind="resource", label=resource["name"], sensitivity=resource["sensitivity"])
        graph.add_edge(
            identity["id"],
            resource["id"],
            relation="temporary",
            permission_id=permission["id"],
            action=permission["action"],
            effective=permission["id"] in granted,
        )
    return graph


def sensitive_paths(directory: Directory, identity: dict, *, include_all: bool = False, include_denied: bool = False) -> list[dict]:
    """Shortest structural paths from the identity to sensitive resources.

    A path is reported only when the policy evaluator also allows the grant.
    Indirect group membership is how a legacy role still reaches a database.
    """
    granted, sources = directory.effective(identity)
    denied = set(identity["deny_permission_ids"])
    if include_denied:
        _structural, sources = directory.effective({**identity, "deny_permission_ids": []})
        granted = _structural
    needed = directory.needs(identity)
    found: list[dict] = []
    for permission_id in sorted(granted):
        permission = directory.permissions[permission_id]
        resource = directory.resources[permission["resource_id"]]
        if not include_all and resource["sensitivity"] not in {"high", "critical"}:
            continue
        for source in sources[permission_id]:
            path = [identity["id"]]
            if source["type"] == "group":
                path.append(source["group_id"])
            if source["type"] in {"group", "role"}:
                path.append(source["role_id"])
            path.append(resource["id"])
            found.append({"permission_id": permission_id, "action": permission["action"],
                          "resource_id": resource["id"], "resource_name": resource["name"],
                          "sensitivity": resource["sensitivity"], "excess": permission_id not in needed,
                          "path": path, "source": source, "effective": permission_id not in denied, "denied": permission_id in denied})
    return found


def graph_payload(directory: Directory, identity: dict) -> dict:
    """JSON graph for the console, limited to the identity ego network."""
    graph = build_ego(directory, identity)
    granted, _sources = directory.effective(identity)
    needed = directory.needs(identity)
    nodes = []
    for node_id, data in graph.nodes(data=True):
        nodes.append({"id": node_id, **data})
    edges = []
    for source, target, _key, data in graph.edges(keys=True, data=True):
        permission_id = data.get("permission_id")
        edges.append(
            {
                "source": source,
                "target": target,
                "relation": data.get("relation"),
                "permission_id": permission_id,
                "action": data.get("action"),
                "effective": data.get("effective"),
                "denied": bool(permission_id and permission_id in identity["deny_permission_ids"]),
                "excess": bool(permission_id and permission_id in granted and permission_id not in needed),
            }
        )
    return {"nodes": nodes, "edges": edges, "paths": sensitive_paths(directory, identity, include_all=True, include_denied=True)}
