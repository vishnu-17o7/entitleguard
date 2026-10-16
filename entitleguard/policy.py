"""RBAC evaluator. A graph edge is not permission; grants and denies are."""
from __future__ import annotations

from collections import defaultdict
from datetime import date

from config import AS_OF


class Directory:
    """Indexes for one enterprise snapshot."""

    def __init__(self, world: dict) -> None:
        self.world = world
        self.resources = {row["id"]: row for row in world["resources"]}
        self.permissions = {row["id"]: row for row in world["permissions"]}
        self.roles = {row["id"]: row for row in world["roles"]}
        self.groups = {row["id"]: row for row in world["groups"]}
        self.identities = {row["id"]: row for row in world["identities"]}
        self.workflows = list(world["workflows"])
        self.exceptions = list(world["exceptions"])
        self.usage = {
            (row["identity_id"], row["permission_id"]): row for row in world["usage"]
        }
        self.labels = {
            (row["identity_id"], row["permission_id"]): row for row in world["labels"]
        }

    def identity(self, identity_id: str) -> dict:
        """Return one identity or raise KeyError."""
        return self.identities[identity_id]

    def role_needs(self, identity: dict) -> set[str]:
        """Permissions documented on the current job role."""
        if identity["status"] != "active":
            return set()
        role = self.roles[identity["role_id"]]
        return set(role["required_permission_ids"])

    def workflow_needs(self, identity: dict) -> set[str]:
        """Permissions required by workflows of the current role."""
        if identity["status"] != "active":
            return set()
        needed: set[str] = set()
        for workflow in self.workflows:
            if identity["role_id"] in workflow["role_ids"]:
                needed.update(workflow["required_permission_ids"])
        return needed

    def exception_needs(self, identity: dict, as_of: str | None = None) -> set[str]:
        """Permissions covered by an active approved exception."""
        if identity["status"] != "active":
            return set()
        return {
            row["permission_id"]
            for row in self.exceptions
            if row["identity_id"] == identity["id"] and row["active"]
            and self.exception_valid(row, as_of or identity.get("_as_of") or self.world.get("meta", {}).get("as_of", AS_OF))
        }

    @staticmethod
    def exception_valid(row: dict, as_of: str) -> bool:
        """An exception covers its inclusive effective and expiry dates."""
        point = date.fromisoformat(as_of[:10])
        start = row.get("effective_on") or row.get("starts_on") or row.get("created_on")
        end = row.get("expires_on")
        return (not start or date.fromisoformat(start[:10]) <= point) and (not end or point <= date.fromisoformat(end[:10]))

    def needs(self, identity: dict) -> set[str]:
        """Documented needs. Unclassified grants are not added here."""
        return self.role_needs(identity) | self.workflow_needs(identity) | self.exception_needs(identity)

    def workflows_for(self, identity: dict) -> list[dict]:
        """Workflows the identity must still be able to run."""
        if identity["status"] != "active":
            return []
        return [row for row in self.workflows if identity["role_id"] in row["role_ids"]]

    def effective(
        self,
        identity: dict,
        *,
        drop_groups: set[str] | None = None,
        drop_permissions: set[str] | None = None,
        drop_expired_temporary: bool = False,
        drop_roles: set[str] | None = None,
        drop_direct: set[str] | None = None,
    ) -> tuple[set[str], dict[str, list[dict[str, str]]]]:
        """Resolve effective permissions and where each grant came from.

        Expired temporary grants still count until they are revoked. That is
        the failure mode the detector is supposed to see. Explicit denies win.
        """
        skipped_groups = drop_groups or set()
        skipped_permissions = drop_permissions or set()
        granted: set[str] = set()
        sources: dict[str, list[dict[str, str]]] = defaultdict(list)

        def add(permission_id: str, source: dict[str, str]) -> None:
            if permission_id in skipped_permissions:
                return
            if permission_id not in self.permissions:
                return
            granted.add(permission_id)
            sources[permission_id].append(source)

        for group_id in identity["group_ids"]:
            if group_id in skipped_groups:
                continue
            group = self.groups[group_id]
            for role_id in group["role_ids"]:
                role = self.roles[role_id]
                for permission_id in role["grant_permission_ids"]:
                    add(
                        permission_id,
                        {"type": "group", "group_id": group_id, "role_id": role_id},
                    )
        for role_id in identity["direct_role_ids"]:
            if role_id in (drop_roles or set()):
                continue
            role = self.roles[role_id]
            for permission_id in role["grant_permission_ids"]:
                add(permission_id, {"type": "role", "role_id": role_id})
        for permission_id in identity["extra_permission_ids"]:
            if permission_id in (drop_direct or set()):
                continue
            add(permission_id, {"type": "direct", "permission_id": permission_id})
        for grant in identity["temporary_grants"]:
            point = identity.get("_as_of") or self.world.get("meta", {}).get("as_of", AS_OF)
            expired = bool(grant.get("expires_on") and grant["expires_on"] < point) if grant.get("expires_on") else bool(grant.get("expired"))
            if drop_expired_temporary and expired:
                continue
            add(
                grant["permission_id"],
                {
                    "type": "temporary",
                    "permission_id": grant["permission_id"],
                    "expired": "yes" if expired else "no",
                },
            )
        for permission_id in identity["deny_permission_ids"]:
            granted.discard(permission_id)
            sources.pop(permission_id, None)
        return granted, dict(sources)

    def usage_for(self, identity_id: str, permission_id: str) -> dict | None:
        """Return the usage aggregate, or None when no log exists."""
        return self.usage.get((identity_id, permission_id))

    def narrowable(self, permission_id: str, needed: set[str]) -> bool:
        """True when a less privileged grant on the same resource is already required."""
        permission = self.permissions[permission_id]
        if not permission["privileged"]:
            return False
        for other_id in needed:
            other = self.permissions.get(other_id)
            if other is None:
                continue
            if other["resource_id"] == permission["resource_id"] and not other["privileged"]:
                return True
        return False
