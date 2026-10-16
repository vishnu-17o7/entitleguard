"""Build a reproducible synthetic enterprise with labeled drift cases."""
from __future__ import annotations

import random
from datetime import date
from typing import Any

from entitleguard.catalog import (
    ACTIONS,
    DEPARTMENTS,
    FIRST_NAMES,
    JOB_ROLES,
    KIND_CYCLE,
    LAST_NAMES,
    P_BILLING_READ,
    P_BILLING_UPDATE,
    P_CUST_SECRET,
    P_DATA_AIRFLOW,
    P_DATA_S3_DELETE,
    P_DATA_S3_GET,
    P_DATA_S3_PUT,
    P_DATA_WH_QUERY,
    P_DATA_WH_WRITE,
    P_HOST_DEPLOY,
    P_IAM_CREATE,
    P_IAM_READ,
    P_LOGS_READ,
    P_RESEARCH_READ,
    P_ML_READ,
    P_ML_REGISTER,
    P_ML_TRAIN,
    P_PAY_RESTORE,
    P_SVC_S3_GET,
    P_TICKET_READ,
    P_TICKET_UPDATE,
    PROJECTS,
    TEAMS,
)
from entitleguard.policy import Directory

from config import AS_OF
from config import HISTORY_START
from config import N_CONTRACTORS
from config import N_EMPLOYEES
from config import N_SERVICES
from config import SEED


def _perm(
    permission_id: str,
    action: str,
    resource_id: str,
    privileged: bool,
    requirement_class: str,
) -> dict[str, Any]:
    return {
        "id": permission_id,
        "action": action,
        "resource_id": resource_id,
        "privileged": privileged,
        "requirement_class": requirement_class,
    }


def _resource(resource_id: str, name: str, kind: str, sensitivity: str, department: str) -> dict[str, str]:
    environment = "prod" if sensitivity in {"high", "critical"} else "staging"
    return {
        "id": resource_id,
        "name": name,
        "kind": kind,
        "sensitivity": sensitivity,
        "environment": environment,
        "department": department,
    }


def build_resources() -> list[dict[str, str]]:
    """Create 200 resources, 25 in each department."""
    resources: list[dict[str, str]] = []
    for department in DEPARTMENTS:
        for index, (kind, sensitivity) in enumerate(KIND_CYCLE):
            resource_id = f"res-{department['id']}-{index:02d}"
            name = f"{department['name']} {kind} {index:02d}"
            resources.append(_resource(resource_id, name, kind, sensitivity, department["id"]))
    names = {
        "res-data-00": "Raw lake bucket",
        "res-data-03": "Customer production warehouse",
        "res-data-04": "Ingestion orchestration",
        "res-ml-05": "Fraud model registry",
        "res-ml-06": "Production customer credentials",
        "res-platform-00": "Integration landing bucket",
        "res-platform-03": "Payments production warehouse",
        "res-platform-10": "Runtime hosts",
        "res-security-07": "Workforce IAM directory",
        "res-security-11": "Detection audit logs",
        "res-finance-08": "Billing ledger",
        "res-support-09": "Customer ticket desk",
    }
    for row in resources:
        if row["id"] in names:
            row["name"] = names[row["id"]]
    return resources


def build_permissions(resources: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Create exactly 150 permissions, including the named demo grants."""
    by_id = {row["id"]: row for row in resources}
    named = [
        _perm(P_DATA_S3_GET, "s3:GetObject", "res-data-00", False, "catalogued"),
        _perm(P_DATA_S3_PUT, "s3:PutObject", "res-data-00", False, "catalogued"),
        _perm(P_DATA_S3_DELETE, "s3:DeleteObject", "res-data-00", True, "catalogued"),
        _perm(P_DATA_AIRFLOW, "airflow:RunDag", "res-data-04", False, "catalogued"),
        _perm(P_DATA_WH_QUERY, "db:Query", "res-data-02", False, "catalogued"),
        _perm(P_DATA_WH_WRITE, "db:Write", "res-data-03", True, "catalogued"),
        _perm(P_ML_READ, "ml:ReadModel", "res-ml-05", False, "catalogued"),
        _perm(P_ML_REGISTER, "ml:RegisterModel", "res-ml-05", True, "catalogued"),
        _perm(P_ML_TRAIN, "ml:CreateTrainingJob", "res-ml-05", True, "catalogued"),
        _perm(P_PAY_RESTORE, "db:Restore", "res-platform-03", True, "catalogued"),
        _perm(P_SVC_S3_GET, "s3:GetObject", "res-platform-00", False, "catalogued"),
        _perm(P_CUST_SECRET, "secrets:Get", "res-ml-06", True, "catalogued"),
        _perm(P_IAM_READ, "iam:Read", "res-security-07", False, "catalogued"),
        _perm(P_IAM_CREATE, "iam:CreateUser", "res-security-07", True, "catalogued"),
        _perm(P_TICKET_READ, "ticket:Read", "res-support-09", False, "catalogued"),
        _perm(P_TICKET_UPDATE, "ticket:Update", "res-support-09", False, "peer_practice"),
        _perm(P_BILLING_READ, "billing:Read", "res-finance-08", False, "catalogued"),
        _perm(P_BILLING_UPDATE, "billing:Update", "res-finance-08", True, "catalogued"),
        _perm(P_HOST_DEPLOY, "host:Deploy", "res-platform-10", True, "catalogued"),
        _perm(P_LOGS_READ, "logs:Read", "res-security-11", False, "catalogued"),
        _perm(P_RESEARCH_READ, "s3:GetObject", "res-research-00", False, "catalogued"),
    ]
    contextual: list[dict[str, Any]] = []
    for index in range(16):
        contextual.append(
            _perm(
                f"p-ctx-aligned-{index:02d}",
                "billing:Read",
                "res-finance-20",
                False,
                "contextual",
            )
        )
    for index in range(16):
        contextual.append(
            _perm(
                f"p-ctx-misaligned-{index:02d}",
                "iam:AttachPolicy",
                "res-security-07",
                True,
                "contextual",
            )
        )
    unclassified: list[dict[str, Any]] = []
    for index in range(10):
        resource = resources[160 + index]
        action, privileged = ACTIONS[resource["kind"]][0]
        unclassified.append(
            _perm(
                f"p-unclassified-{index:02d}",
                action,
                resource["id"],
                privileged,
                "unclassified",
            )
        )
    permissions = list(named) + contextual + unclassified
    used_resources = {row["resource_id"] for row in named}
    for resource in resources:
        if len(permissions) >= 150:
            break
        if resource["id"] in used_resources:
            continue
        action, privileged = ACTIONS[resource["kind"]][0]
        permissions.append(
            _perm(
                f"p-{resource['id']}",
                action,
                resource["id"],
                privileged,
                "catalogued",
            )
        )
        used_resources.add(resource["id"])
    if len(permissions) != 150:
        raise RuntimeError(f"expected 150 permissions, got {len(permissions)}")
    for row in permissions:
        if row["resource_id"] not in by_id:
            raise RuntimeError(f"missing resource {row['resource_id']}")
    return permissions


def _pool(permissions: list[dict[str, Any]], department: str, resources: dict[str, dict]) -> list[str]:
    rows = [
        row["id"]
        for row in permissions
        if row["requirement_class"] == "catalogued"
        and resources[row["resource_id"]]["department"] == department
        and not row["id"].startswith("p-pay")
        and row["id"] != P_CUST_SECRET
    ]
    return rows


def build_roles(permissions: list[dict[str, Any]], resources: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Create 30 job roles plus two grant bundles used only by groups."""
    resource_index = {row["id"]: row for row in resources}
    pools = {
        department["id"]: _pool(permissions, department["id"], resource_index)
        for department in DEPARTMENTS
    }
    manual: dict[str, list[str]] = {
        "data-engineer": [P_DATA_S3_GET, P_DATA_S3_PUT, P_DATA_AIRFLOW, P_DATA_WH_QUERY, P_DATA_WH_WRITE],
        "analytics-engineer": [P_DATA_S3_GET, P_DATA_WH_QUERY],
        "data-steward": [P_DATA_WH_QUERY],
        "data-manager": [P_DATA_S3_GET, P_DATA_AIRFLOW, P_DATA_WH_QUERY],
        "ml-engineer": [P_ML_READ, P_ML_REGISTER, P_ML_TRAIN],
        "fraud-ml-engineer": [P_ML_READ, P_ML_REGISTER, P_ML_TRAIN],
        "ml-scientist": [P_ML_READ],
        "ml-operator": [P_ML_READ, P_ML_TRAIN],
        "finance-analyst": [P_BILLING_READ],
        "billing-admin": [P_BILLING_READ, P_BILLING_UPDATE],
        "payroll": [P_BILLING_READ],
        "contractor-analyst": [P_BILLING_READ],
        "security-analyst": [P_LOGS_READ],
        "iam-admin": [P_IAM_READ, P_IAM_CREATE],
        "detection-engineer": [P_LOGS_READ],
        "breakglass": [P_IAM_READ],
        "devops": [P_HOST_DEPLOY],
        "sre": [P_HOST_DEPLOY, P_LOGS_READ],
        "recovery-engineer": [P_HOST_DEPLOY],
        "service-owner": [P_SVC_S3_GET],
        "eng-manager": [P_HOST_DEPLOY],
        "support-agent": [P_TICKET_READ],
        "support-lead": [P_TICKET_READ, P_TICKET_UPDATE],
        "knowledge": [P_TICKET_READ],
        "research-scientist": [P_RESEARCH_READ],
        "research-engineer": [P_RESEARCH_READ],
        "lab-coordinator": [P_RESEARCH_READ],
        "it-support": [],
        "it-admin": [],
        "endpoint": [],
    }
    roles: list[dict[str, Any]] = []
    for spec in JOB_ROLES:
        pool = pools[spec["department"]]
        grants = list(dict.fromkeys(manual[spec["id"]] + pool[:4]))
        if spec["id"] == "service-owner":
            grants = [P_SVC_S3_GET]
        if spec["id"] == "recovery-engineer":
            grants = [permission_id for permission_id in grants if permission_id != P_PAY_RESTORE]
        if spec["id"] == "support-agent":
            grants = [permission_id for permission_id in grants if permission_id != P_TICKET_UPDATE]
        if spec["id"] == "data-engineer":
            grants = [permission_id for permission_id in grants if permission_id != P_DATA_S3_DELETE]
        if spec["id"] in {"finance-analyst", "payroll", "contractor-analyst"}:
            grants = [permission_id for permission_id in grants if permission_id != P_BILLING_UPDATE]
        roles.append(
            {
                "id": spec["id"],
                "title": spec["title"],
                "department": spec["department"],
                "duty": spec["duty"],
                "job_role": True,
                "grant_permission_ids": grants,
                "required_permission_ids": list(grants),
            }
        )
    roles.append(
        {
            "id": "bundle-recovery-drill",
            "title": "Quarterly recovery drill",
            "department": "platform",
            "duty": "Restore the payments warehouse on the quarterly drill",
            "job_role": False,
            "grant_permission_ids": [P_PAY_RESTORE],
            "required_permission_ids": [P_PAY_RESTORE],
        }
    )
    roles.append(
        {
            "id": "bundle-support-update",
            "title": "Ticket update practice",
            "department": "support",
            "duty": "Update customer tickets",
            "job_role": False,
            "grant_permission_ids": [P_TICKET_UPDATE],
            "required_permission_ids": [],
        }
    )
    return roles


def build_groups(roles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One group per job role, plus the drill bundle and the support practice group."""
    groups = []
    for role in roles:
        if not role["job_role"]:
            continue
        groups.append(
            {
                "id": f"grp-{role['id']}",
                "name": role["title"],
                "role_ids": [role["id"]],
                "purpose": "job",
                "department": role["department"],
            }
        )
    groups.append(
        {
            "id": "grp-recovery-drill",
            "name": "Quarterly recovery drill",
            "role_ids": ["bundle-recovery-drill"],
            "purpose": "workflow",
            "department": "platform",
        }
    )
    groups.append(
        {
            "id": "grp-support-practice",
            "name": "Support ticket update practice",
            "role_ids": ["bundle-support-update"],
            "purpose": "peer",
            "department": "support",
        }
    )
    return groups


def build_workflows() -> list[dict[str, Any]]:
    """Business workflows. The quarterly restore is not on the job-role document."""
    return [
        {
            "id": "wf-fraud-train",
            "name": "Train fraud model",
            "cadence": "daily",
            "role_ids": ["ml-engineer", "fraud-ml-engineer"],
            "required_permission_ids": [P_ML_TRAIN, P_ML_REGISTER, P_ML_READ],
        },
        {
            "id": "wf-data-pipeline",
            "name": "Daily lake pipeline",
            "cadence": "daily",
            "role_ids": ["data-engineer"],
            "required_permission_ids": [P_DATA_S3_GET, P_DATA_S3_PUT, P_DATA_AIRFLOW, P_DATA_WH_WRITE],
        },
        {
            "id": "wf-quarterly-restore",
            "name": "Quarterly payments restore",
            "cadence": "quarterly",
            "role_ids": ["recovery-engineer"],
            "required_permission_ids": [P_PAY_RESTORE],
        },
        {
            "id": "wf-deploy",
            "name": "Production deploy",
            "cadence": "weekly",
            "role_ids": ["devops", "sre", "eng-manager"],
            "required_permission_ids": [P_HOST_DEPLOY],
        },
        {
            "id": "wf-billing-close",
            "name": "Monthly billing close",
            "cadence": "monthly",
            "role_ids": ["finance-analyst", "billing-admin", "payroll"],
            "required_permission_ids": [P_BILLING_READ],
        },
        {
            "id": "wf-iam-joiners",
            "name": "Joiner account provisioning",
            "cadence": "daily",
            "role_ids": ["iam-admin"],
            "required_permission_ids": [P_IAM_READ, P_IAM_CREATE],
        },
    ]


def _person_name(index: int) -> str:
    first = FIRST_NAMES[index % len(FIRST_NAMES)]
    last = LAST_NAMES[(index // len(FIRST_NAMES)) % len(LAST_NAMES)]
    return f"{first} {last}"


def _base_identity(
    identity_id: str,
    *,
    name: str,
    kind: str,
    role: dict[str, Any],
    team_index: int,
    status: str = "active",
) -> dict[str, Any]:
    department = role["department"]
    return {
        "id": identity_id,
        "name": name,
        "kind": kind,
        "role_id": role["id"],
        "department": department,
        "team": TEAMS[department][team_index % len(TEAMS[department])],
        "projects": [PROJECTS[department][team_index % len(PROJECTS[department])]],
        "status": status,
        "group_ids": [f"grp-{role['id']}"],
        "direct_role_ids": [],
        "extra_permission_ids": [],
        "deny_permission_ids": [],
        "temporary_grants": [],
        "responsibility": role["duty"],
        "role_history": [
            {
                "date": "2026-04-17",
                "role_id": role["id"],
                "group_ids": [f"grp-{role['id']}"],
            }
        ],
        "scenarios": [],
        "split": "train",
        "showcase": None,
    }


HOLDOUT_SCENARIOS = {
    "lingering_role",
    "quarterly_recovery",
    "excess_service",
    "expired_contractor",
    "mistaken_group",
    "contextual_aligned",
    "contextual_misaligned",
    "missing_usage",
    "approved_exception",
    "unknown_requirement",
}


def _set_split(identity: dict[str, Any]) -> None:
    scenarios = set(identity["scenarios"])
    if identity.get("force_split"):
        identity["split"] = identity["force_split"]
    elif identity["department"] in {"research", "it"}:
        identity["split"] = "test"
    elif scenarios & HOLDOUT_SCENARIOS:
        identity["split"] = "test"
    elif identity["showcase"]:
        identity["split"] = "test"
    else:
        identity["split"] = "train"


def _add_label(
    labels: list[dict[str, Any]],
    identity: dict[str, Any],
    permission_id: str,
    scenario: str,
    expected: str,
    *,
    y_unjustified: int,
    y_legitimate: int,
) -> None:
    labels.append(
        {
            "identity_id": identity["id"],
            "permission_id": permission_id,
            "scenario": scenario,
            "expected": expected,
            "y_unjustified": y_unjustified,
            "y_legitimate": y_legitimate,
        }
    )


def _apply_faults(
    identities: list[dict[str, Any]],
    permissions: list[dict[str, Any]],
    labels: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
) -> None:
    by_id = {row["id"]: row for row in identities}
    by_role: dict[str, list[dict[str, Any]]] = {}
    for row in identities:
        by_role.setdefault(row["role_id"], []).append(row)

    maya = by_id["EMP-104"]
    maya.update(
        {
            "name": "Maya Krishnan",
            "role_id": "ml-engineer",
            "department": "ml",
            "team": "Fraud Detection",
            "projects": ["fraud-model-v2"],
            "responsibility": "Train fraud models for fraud-model-v2",
            "group_ids": ["grp-ml-engineer", "grp-data-engineer"],
            "showcase": "role-transfer",
            "scenarios": ["lingering_role"],
        }
    )
    maya["role_history"] = [
        {"date": "2026-04-17", "role_id": "data-engineer", "group_ids": ["grp-data-engineer"]},
        {"date": "2026-07-01", "role_id": "ml-engineer", "group_ids": ["grp-ml-engineer", "grp-data-engineer"]},
    ]
    for permission_id in (P_DATA_S3_GET, P_DATA_S3_PUT, P_DATA_AIRFLOW, P_DATA_WH_QUERY, P_DATA_WH_WRITE):
        _add_label(labels, maya, permission_id, "lingering_role", "remove", y_unjustified=1, y_legitimate=0)
    for permission_id in (P_ML_READ, P_ML_REGISTER, P_ML_TRAIN):
        _add_label(labels, maya, permission_id, "necessary_current", "retain", y_unjustified=0, y_legitimate=1)

    arun = by_id["EMP-027"]
    arun.update(
        {
            "name": "Arun Desai",
            "role_id": "recovery-engineer",
            "department": "platform",
            "team": "Recovery",
            "projects": ["payments-dr"],
            "responsibility": "Restore production data during quarterly recovery drills",
            "group_ids": ["grp-recovery-engineer", "grp-recovery-drill"],
            "showcase": "quarterly-recovery",
            "scenarios": ["quarterly_recovery"],
        }
    )
    arun["role_history"] = [
        *arun["role_history"],
        {
            "date": "2026-07-01",
            "role_id": "recovery-engineer",
            "group_ids": ["grp-recovery-engineer", "grp-recovery-drill"],
        },
    ]
    _add_label(labels, arun, P_PAY_RESTORE, "quarterly_recovery", "retain", y_unjustified=0, y_legitimate=1)
    _add_label(labels, arun, P_HOST_DEPLOY, "necessary_current", "retain", y_unjustified=0, y_legitimate=1)

    svc = by_id["SVC-018"]
    svc.update(
        {
            "name": "svc-etl-legacy",
            "role_id": "service-owner",
            "department": "platform",
            "team": "Delivery",
            "projects": ["runtime-rollout"],
            "responsibility": "Read the integration landing bucket",
            "group_ids": ["grp-service-owner"],
            "extra_permission_ids": [P_CUST_SECRET, P_IAM_CREATE],
            "showcase": "excess-service",
            "scenarios": ["excess_service"],
        }
    )
    svc["role_history"] = [
        *svc["role_history"],
        {
            "date": "2026-07-01",
            "role_id": "service-owner",
            "group_ids": ["grp-service-owner"],
            "extra_permission_ids": [P_CUST_SECRET, P_IAM_CREATE],
        },
    ]
    _add_label(labels, svc, P_CUST_SECRET, "excess_service", "remove", y_unjustified=1, y_legitimate=0)
    _add_label(labels, svc, P_IAM_CREATE, "excess_service", "remove", y_unjustified=1, y_legitimate=0)
    _add_label(labels, svc, P_SVC_S3_GET, "necessary_current", "retain", y_unjustified=0, y_legitimate=1)

    # More lingering transfers: data engineers who became ML engineers.
    transfers = [row for row in by_role.get("ml-engineer", []) if row["id"] != "EMP-104"][:4]
    for row in transfers:
        row["group_ids"] = ["grp-ml-engineer", "grp-data-engineer"]
        row["scenarios"] = ["lingering_role"]
        row["role_history"] = [
            {"date": "2026-04-17", "role_id": "data-engineer", "group_ids": ["grp-data-engineer"]},
            {"date": "2026-07-01", "role_id": "ml-engineer", "group_ids": row["group_ids"]},
        ]
        row["responsibility"] = "Train and register models after leaving the data platform"
        _add_label(labels, row, P_DATA_WH_WRITE, "lingering_role", "remove", y_unjustified=1, y_legitimate=0)

    # Scope that can be narrowed: delete on the raw bucket beside a required read.
    narrow_cases = [row for row in by_role.get("data-engineer", []) if "lingering_role" not in row["scenarios"]][:4]
    for row in narrow_cases:
        row["extra_permission_ids"] = [P_DATA_S3_DELETE]
        row["scenarios"] = ["excess_scope"]
        _add_label(labels, row, P_DATA_S3_DELETE, "excess_scope", "reduce", y_unjustified=1, y_legitimate=0)

    # Expired temporary admin still effective.
    temps = [row for row in by_role.get("devops", []) if not row["scenarios"]][:4]
    for row in temps:
        row["temporary_grants"] = [
            {"permission_id": P_IAM_CREATE, "expires_on": "2026-06-01", "expired": True}
        ]
        row["scenarios"] = ["temp_admin_expired"]
        _add_label(labels, row, P_IAM_CREATE, "temp_admin_expired", "remove", y_unjustified=1, y_legitimate=0)

    # Expired contractors who were active in the logs last week.
    contractors = [row for row in by_role.get("contractor-analyst", []) if not row["scenarios"]][:N_CONTRACTORS]
    for row in contractors:
        row["kind"] = "contractor"
        row["status"] = "expired"
        row["scenarios"] = ["expired_contractor"]
        _add_label(labels, row, P_BILLING_READ, "expired_contractor", "remove", y_unjustified=1, y_legitimate=0)

    # Support agents placed in the IAM admin group by mistake.
    mistaken = [row for row in by_role.get("support-agent", []) if not row["scenarios"]][:4]
    for row in mistaken:
        row["group_ids"] = ["grp-support-agent", "grp-iam-admin"]
        row["scenarios"] = ["mistaken_group"]
        _add_label(labels, row, P_IAM_CREATE, "mistaken_group", "remove", y_unjustified=1, y_legitimate=0)

    # Stale research group on finance analysts.
    stale = [row for row in by_role.get("finance-analyst", []) if not row["scenarios"]][:4]
    for row in stale:
        row["group_ids"] = ["grp-finance-analyst", "grp-research-scientist"]
        row["scenarios"] = ["stale_project"]
        _add_label(labels, row, P_RESEARCH_READ, "stale_project", "remove", y_unjustified=1, y_legitimate=0)

    # Other recovery engineers: the drill grant is legitimate and rarely used.
    for row in by_role.get("recovery-engineer", []):
        if row["id"] == "EMP-027":
            continue
        if "grp-recovery-drill" not in row["group_ids"]:
            row["group_ids"] = ["grp-recovery-engineer", "grp-recovery-drill"]
        row["scenarios"] = ["quarterly_recovery"]
        row["responsibility"] = "Restore production data during quarterly recovery drills"
        _add_label(labels, row, P_PAY_RESTORE, "quarterly_recovery", "retain", y_unjustified=0, y_legitimate=1)

    # Necessary privileged admin, used yesterday.
    for row in by_role.get("iam-admin", [])[:8]:
        if row["scenarios"]:
            continue
        row["scenarios"] = ["necessary_admin"]
        _add_label(labels, row, P_IAM_CREATE, "necessary_admin", "retain", y_unjustified=0, y_legitimate=1)

    # Unclassified holdings. The right response is review, not removal.
    unclassified = [row["id"] for row in permissions if row["requirement_class"] == "unclassified"]
    holders = [row for row in identities if row["kind"] == "employee" and not row["scenarios"]][:10]
    for row, permission_id in zip(holders, unclassified):
        row["extra_permission_ids"] = [permission_id]
        row["scenarios"] = ["unknown_requirement"]
        _add_label(labels, row, permission_id, "unknown_requirement", "review", y_unjustified=0, y_legitimate=1)

    # Contextual cases. The duty text is visible to Jev. The label is not.
    contextual_pool = [row for row in identities if row["kind"] == "employee" and not row["scenarios"]]
    aligned = contextual_pool[:16]
    misaligned = contextual_pool[16:32]
    for index, row in enumerate(aligned):
        permission_id = f"p-ctx-aligned-{index:02d}"
        row["extra_permission_ids"] = [permission_id]
        row["responsibility"] = "Prepare the quarterly billing extract for finance close"
        row["scenarios"] = ["contextual_aligned"]
        _add_label(labels, row, permission_id, "contextual_aligned", "review", y_unjustified=0, y_legitimate=1)
    for index, row in enumerate(misaligned):
        permission_id = f"p-ctx-misaligned-{index:02d}"
        row["extra_permission_ids"] = [permission_id]
        row["responsibility"] = "Model warehouse tables for analysts"
        row["scenarios"] = ["contextual_misaligned"]
        _add_label(labels, row, permission_id, "contextual_misaligned", "remove", y_unjustified=1, y_legitimate=0)

    # Approved migration exception with no expiry: keep it temporary.
    exception_people = [row for row in by_role.get("finance-analyst", []) if not row["scenarios"]][:4]
    for row in exception_people:
        row["extra_permission_ids"] = [P_BILLING_UPDATE]
        row["scenarios"] = ["approved_exception"]
        row["responsibility"] = "Update billing records for the July migration window"
        exceptions.append(
            {
                "identity_id": row["id"],
                "permission_id": P_BILLING_UPDATE,
                "active": True,
                "expires_on": None,
                "reason": "July billing migration, no end date recorded",
            }
        )
        _add_label(labels, row, P_BILLING_UPDATE, "approved_exception", "temporary", y_unjustified=0, y_legitimate=1)

    # Support agents carry the undocumented ticket update. Peer prevalence is high.
    for row in by_role.get("support-agent", []):
        if "grp-support-practice" not in row["group_ids"]:
            row["group_ids"] = list(dict.fromkeys([*row["group_ids"], "grp-support-practice"]))
        if "mistaken_group" in row["scenarios"]:
            continue
        if "peer_practice" not in row["scenarios"]:
            row["scenarios"] = [*row["scenarios"], "peer_practice"]
    peer_sample = [row for row in by_role.get("support-agent", []) if "mistaken_group" not in row["scenarios"]][:12]
    for index, row in enumerate(peer_sample):
        if index < 5:
            row["force_split"] = "test"
        _add_label(labels, row, P_TICKET_UPDATE, "peer_practice", "review", y_unjustified=0, y_legitimate=1)

    # A few excess grants with no activity log. Removal is not proven safe.
    missing = [row for row in by_role.get("sre", []) if not row["scenarios"]][:4]
    for row in missing:
        row["extra_permission_ids"] = [P_CUST_SECRET]
        row["scenarios"] = ["missing_usage"]
        _add_label(labels, row, P_CUST_SECRET, "missing_usage", "review", y_unjustified=0, y_legitimate=1)

    # Extra service accounts with the same excess pair as SVC-018.
    services = [row for row in identities if row["kind"] == "service" and row["id"] != "SVC-018"][:7]
    for row in services:
        row["extra_permission_ids"] = [P_CUST_SECRET, P_IAM_CREATE]
        row["scenarios"] = ["excess_service"]
        _add_label(labels, row, P_CUST_SECRET, "excess_service", "remove", y_unjustified=1, y_legitimate=0)
        _add_label(labels, row, P_IAM_CREATE, "excess_service", "remove", y_unjustified=1, y_legitimate=0)

    for row in identities:
        _set_split(row)


def _usage_days(identity: dict[str, Any], permission_id: str, rng: random.Random) -> int | None:
    scenarios = set(identity["scenarios"])
    if "missing_usage" in scenarios and permission_id == P_CUST_SECRET:
        return None
    if permission_id == P_PAY_RESTORE or "quarterly_recovery" in scenarios and permission_id == P_PAY_RESTORE:
        return 91
    if "lingering_role" in scenarios and permission_id in {
        P_DATA_S3_GET, P_DATA_S3_PUT, P_DATA_AIRFLOW, P_DATA_WH_QUERY, P_DATA_WH_WRITE,
    }:
        return rng.randint(120, 180)
    if "temp_admin_expired" in scenarios and permission_id == P_IAM_CREATE:
        return rng.randint(70, 110)
    if "expired_contractor" in scenarios:
        return rng.randint(3, 12)
    if "necessary_admin" in scenarios and permission_id == P_IAM_CREATE:
        return 1
    if "excess_service" in scenarios and permission_id in {P_CUST_SECRET, P_IAM_CREATE}:
        return rng.randint(100, 180)
    if "stale_project" in scenarios and permission_id == P_RESEARCH_READ:
        return rng.randint(100, 160)
    if "excess_scope" in scenarios and permission_id == P_DATA_S3_DELETE:
        return rng.randint(40, 80)
    if "contextual_misaligned" in scenarios and permission_id.startswith("p-ctx-misaligned"):
        return rng.randint(30, 90)
    if "contextual_aligned" in scenarios and permission_id.startswith("p-ctx-aligned"):
        return rng.randint(20, 70)
    return rng.randint(0, 14)


def _activity_for(identity: dict[str, Any], permission_id: str, days: int) -> dict[str, Any]:
    return {
        "identity_id": identity["id"],
        "permission_id": permission_id,
        "last_used_days": days,
        "use_count_180d": 1 if days > 60 else 12,
        "outcome": "success",
    }


def generate_enterprise(seed: int = SEED, as_of: str = AS_OF) -> dict[str, Any]:
    """Return the full synthetic enterprise. Counts match the plan's initial target."""
    date.fromisoformat(as_of)
    rng = random.Random(seed)
    resources = build_resources()
    permissions = build_permissions(resources)
    roles = build_roles(permissions, resources)
    groups = build_groups(roles)
    workflows = build_workflows()
    job_roles = [row for row in roles if row["job_role"]]
    identities: list[dict[str, Any]] = []
    for number in range(1, N_EMPLOYEES + 1):
        role = job_roles[(number - 1) % len(job_roles)]
        identities.append(
            _base_identity(
                f"EMP-{number:03d}",
                name=_person_name(number),
                kind="employee",
                role=role,
                team_index=number,
            )
        )
    service_role = next(row for row in job_roles if row["id"] == "service-owner")
    for number in range(1, N_SERVICES + 1):
        identities.append(
            _base_identity(
                f"SVC-{number:03d}",
                name=f"svc-integration-{number:03d}",
                kind="service",
                role=service_role,
                team_index=number,
            )
        )
    labels: list[dict[str, Any]] = []
    exceptions: list[dict[str, Any]] = []
    _apply_faults(identities, permissions, labels, exceptions)

    world: dict[str, Any] = {
        "meta": {
            "seed": seed,
            "as_of": as_of,
            "history_start": HISTORY_START,
            "employees": N_EMPLOYEES,
            "service_accounts": N_SERVICES,
            "departments": len(DEPARTMENTS),
            "job_roles": len(job_roles),
            "resources": len(resources),
            "permissions": len(permissions),
            "note": "Synthetic enterprise. Illustrative identities, not a real company.",
        },
        "departments": DEPARTMENTS,
        "resources": resources,
        "permissions": permissions,
        "roles": roles,
        "groups": groups,
        "workflows": workflows,
        "identities": identities,
        "exceptions": exceptions,
        "labels": labels,
        "usage": [],
        "activity": [],
    }
    directory = Directory(world)
    usage: list[dict[str, Any]] = []
    activity: list[dict[str, Any]] = []
    for identity in identities:
        granted, _sources = directory.effective(identity)
        for permission_id in sorted(granted):
            days = _usage_days(identity, permission_id, rng)
            if days is None:
                continue
            usage.append(_activity_for(identity, permission_id, days))
            if identity["showcase"] or identity["id"] in {"EMP-104", "EMP-027", "SVC-018"}:
                activity.append(
                    {
                        "identity_id": identity["id"],
                        "permission_id": permission_id,
                        "days_ago": days,
                        "action": directory.permissions[permission_id]["action"],
                        "result": "success",
                    }
                )
    # Independent seed variation changes source redundancy and missing-log evidence.
    # Teaching cases and existing labeled scenarios stay stable.
    noise_rng = random.Random(seed + 1701)
    for identity in identities:
        if identity["showcase"] or identity["id"] in {"EMP-104", "EMP-027", "SVC-018"} or identity["scenarios"]:
            continue
        required = directory.roles[identity["role_id"]]["required_permission_ids"]
        if required and noise_rng.random() < 0.25:
            identity["extra_permission_ids"] = list(dict.fromkeys([*identity["extra_permission_ids"], noise_rng.choice(required)]))
        if required and noise_rng.random() < 0.12:
            pid = noise_rng.choice(required)
            usage = [row for row in usage if (row["identity_id"], row["permission_id"]) != (identity["id"], pid)]
            _add_label(labels, identity, pid, "documented_missing_log", "retain", y_unjustified=0, y_legitimate=1)
        elif required and noise_rng.random() < 0.15:
            pid = noise_rng.choice(required)
            for row in usage:
                if (row["identity_id"], row["permission_id"]) == (identity["id"], pid):
                    row["last_used_days"] = noise_rng.choice([89, 90, 91, 179])
            _add_label(labels, identity, pid, "documented_recency_boundary", "retain", y_unjustified=0, y_legitimate=1)
    # Predeclared identity partitions provide validation/test representatives for
    # fault families that the original split placed entirely in training.
    for scenario in ("excess_scope", "temp_admin_expired", "stale_project", "necessary_admin"):
        members = sorted([row for row in identities if scenario in row["scenarios"] and not row["showcase"]], key=lambda row: row["id"])
        if len(members) >= 3:
            members[1]["split"] = "validation"
            members[2]["split"] = "test"
    # Freeze split by identity, never by grants; showcase test assignments remain fixed.
    for identity in identities:
        if identity["split"] == "train" and int(identity["id"].split("-")[-1]) % 5 == 0:
            identity["split"] = "validation"
    world["meta"]["population"] = {
        kind: sum(row["kind"] == kind for row in identities)
        for kind in ("employee", "contractor", "service")
    }
    world["meta"]["variation"] = "Recency, redundant direct sources, missing logs; shared scenario templates across seeds."
    world["meta"]["splits"] = {
        split: sorted(row["id"] for row in identities if row["split"] == split)
        for split in ("train", "validation", "test")
    }
    world["usage"] = usage
    world["activity"] = activity
    world["meta"]["permissions"] = len(permissions)
    return world
