"""Automatic assessment on a temporary world. No hosted model and no project ledger."""
from __future__ import annotations

import copy
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from api import create_app
from entitleguard.artifacts import provenance
from entitleguard.assess import protected_reason
from entitleguard.assess import run_assessment
from entitleguard.jobs import RunManager
from entitleguard.pipeline import analyze_world


def _identity(identity_id: str, *, role_id: str, groups: list[str], extra: list[str] | None = None, temporary: list[dict] | None = None) -> dict:
    return {
        "id": identity_id,
        "name": identity_id,
        "kind": "employee",
        "role_id": role_id,
        "department": "lab",
        "team": "Review",
        "projects": ["assessment"],
        "status": "active",
        "group_ids": list(groups),
        "direct_role_ids": [],
        "extra_permission_ids": list(extra or []),
        "deny_permission_ids": [],
        "temporary_grants": list(temporary or []),
        "responsibility": "Keep documented duties and drop only verified excess",
        "role_history": [{"date": "2026-04-17", "role_id": role_id, "group_ids": list(groups)}],
        "scenarios": [],
        "split": "train",
        "showcase": None,
    }


def build_world() -> dict:
    """A small enterprise with one safe removal and several protected grants."""
    resources = [
        ("res-duty", "Duty warehouse", "critical"),
        ("res-read", "Duty bucket", "low"),
        ("res-safe", "Old export", "low"),
        ("res-crit", "Legacy vault", "critical"),
        ("res-miss", "Unlogged archive", "high"),
        ("res-except", "Migration ledger", "high"),
        ("res-delete", "Duty bucket", "high"),
        ("res-redundant", "Shared scratch", "medium"),
        ("res-temp", "Expired admin", "medium"),
        ("res-stuck", "Bundle-only secret", "high"),
    ]
    permissions = [
        ("perm-duty", "db:Restore", "res-duty", False),
        ("perm-read", "bucket:Read", "res-read", False),
        ("perm-safe", "export:Read", "res-safe", False),
        ("perm-crit", "vault:Admin", "res-crit", True),
        ("perm-miss", "archive:Read", "res-miss", False),
        ("perm-except", "ledger:Update", "res-except", False),
        ("perm-delete", "bucket:Delete", "res-delete", True),
        ("perm-redundant", "scratch:Write", "res-redundant", False),
        ("perm-temp", "admin:Create", "res-temp", True),
        ("perm-stuck", "secret:Get", "res-stuck", True),
    ]
    # Delete is narrowable only when a less privileged grant shares its resource.
    permissions[6] = ("perm-delete", "bucket:Delete", "res-read", True)
    world = {
        "meta": {"seed": 7, "as_of": "2026-10-14", "history_start": "2026-04-17"},
        "resources": [{"id": item[0], "name": item[1], "kind": "store", "sensitivity": item[2], "environment": "prod", "department": "lab"} for item in resources],
        "permissions": [{"id": item[0], "action": item[1], "resource_id": item[2], "privileged": item[3], "requirement_class": "catalogued"} for item in permissions],
        "roles": [
            {"id": "role-job", "title": "Reviewer", "department": "lab", "duty": "Run the documented duty", "required_permission_ids": ["perm-duty", "perm-read"], "grant_permission_ids": ["perm-duty", "perm-read"], "job_role": True},
            {"id": "role-legacy", "title": "Legacy scratch", "department": "lab", "duty": "Old scratch access", "required_permission_ids": [], "grant_permission_ids": ["perm-redundant"], "job_role": False},
            {"id": "role-bundle", "title": "Bundled secret", "department": "lab", "duty": "Duty plus a secret", "required_permission_ids": ["perm-duty"], "grant_permission_ids": ["perm-duty", "perm-stuck"], "job_role": False},
        ],
        "groups": [
            {"id": "grp-job", "name": "Reviewers", "purpose": "job", "department": "lab", "role_ids": ["role-job"]},
            {"id": "grp-legacy", "name": "Legacy scratch", "purpose": "job", "department": "lab", "role_ids": ["role-legacy"]},
            {"id": "grp-bundle", "name": "Bundled secret", "purpose": "job", "department": "lab", "role_ids": ["role-bundle"]},
        ],
        "workflows": [{"id": "wf-duty", "name": "Quarterly duty", "cadence": "quarterly", "role_ids": ["role-job"], "required_permission_ids": ["perm-duty"]}],
        "identities": [
            _identity("EMP-1", role_id="role-job", groups=["grp-job"], extra=["perm-safe", "perm-crit", "perm-miss", "perm-except", "perm-delete", "perm-duty"]),
            _identity("EMP-2", role_id="role-job", groups=["grp-job", "grp-legacy"], extra=["perm-redundant"]),
            _identity("EMP-3", role_id="role-job", groups=["grp-job"], temporary=[{"permission_id": "perm-temp", "expires_on": "2026-06-01", "expired": True}]),
            _identity("EMP-STUCK", role_id="role-job", groups=["grp-bundle"]),
            _identity("EMP-A", role_id="role-job", groups=["grp-job"]),
            _identity("EMP-B", role_id="role-job", groups=["grp-job"]),
        ],
        "usage": [],
        "exceptions": [{"identity_id": "EMP-1", "permission_id": "perm-except", "active": True, "effective_on": "2026-01-01", "expires_on": "2026-12-31", "reason": "Approved migration window"}],
        "labels": [],
        "activity": [],
    }
    usage = {
        "EMP-1": {"perm-duty": 200, "perm-read": 4, "perm-safe": 40, "perm-crit": 20, "perm-except": 5, "perm-delete": 12},
        "EMP-2": {"perm-duty": 3, "perm-read": 3, "perm-redundant": 30},
        "EMP-3": {"perm-duty": 3, "perm-read": 3, "perm-temp": 8},
        "EMP-STUCK": {"perm-duty": 180, "perm-stuck": 50},
        "EMP-A": {"perm-duty": 2, "perm-read": 2},
        "EMP-B": {"perm-duty": 2, "perm-read": 2},
    }
    for identity_id, grants in usage.items():
        for permission_id, days in grants.items():
            world["usage"].append({"identity_id": identity_id, "permission_id": permission_id, "last_used_days": days, "use_count_180d": 2})
    return world


def _decision(result: dict, identity_id: str, permission_id: str) -> dict:
    return next(row for row in result["decisions"] if row["identity_id"] == identity_id and row["permission_id"] == permission_id)


class AssessmentPolicyTests(unittest.TestCase):
    def test_safe_removals_and_protected_grants(self) -> None:
        world = build_world()
        original = copy.deepcopy(world)
        result = run_assessment(world)
        self.assertEqual(world, original)
        self.assertEqual(world["roles"][0]["grant_permission_ids"], ["perm-duty", "perm-read"])
        final = {row["id"]: row for row in result["final_world"]["identities"]}
        kept = {row["permission_id"] for row in result["final_analysis"]["identities"]["EMP-1"]["permissions"]}
        self.assertNotIn("perm-safe", kept)
        self.assertNotIn("perm-crit", kept)
        self.assertIn("perm-duty", kept)
        self.assertIn("perm-miss", kept)
        self.assertIn("perm-except", kept)
        self.assertIn("perm-delete", kept)
        self.assertIn("perm-duty", final["EMP-1"]["extra_permission_ids"])
        self.assertNotIn("perm-redundant", {row["permission_id"] for row in result["final_analysis"]["identities"]["EMP-2"]["permissions"]})
        self.assertNotIn("grp-legacy", final["EMP-2"]["group_ids"])
        self.assertNotIn("perm-redundant", final["EMP-2"]["extra_permission_ids"])
        self.assertEqual(final["EMP-3"]["temporary_grants"], [])
        self.assertNotIn("perm-temp", {row["permission_id"] for row in result["final_analysis"]["identities"]["EMP-3"]["permissions"]})
        self.assertIn("perm-stuck", {row["permission_id"] for row in result["final_analysis"]["identities"]["EMP-STUCK"]["permissions"]})
        self.assertIn("grp-bundle", final["EMP-STUCK"]["group_ids"])
        duty = _decision(result, "EMP-1", "perm-duty")
        critical = _decision(result, "EMP-1", "perm-crit")
        missing = _decision(result, "EMP-1", "perm-miss")
        exception = _decision(result, "EMP-1", "perm-except")
        narrowed = _decision(result, "EMP-1", "perm-delete")
        stuck = _decision(result, "EMP-STUCK", "perm-stuck")
        self.assertEqual(duty["decision"], "hold")
        self.assertIn("workflow", duty["rationale"])
        self.assertFalse(duty["applied"])
        self.assertFalse(duty["applied_in_simulation"])
        self.assertEqual(critical["decision"], "apply")
        self.assertTrue(critical["applied_in_simulation"])
        self.assertFalse(critical["applied"])
        self.assertIn("did not authorize", critical["rationale"])
        self.assertGreaterEqual(critical["risk"]["severity"], 0.7)
        self.assertEqual(missing["decision"], "hold")
        self.assertIn("Usage evidence", missing["rationale"])
        self.assertEqual(exception["decision"], "hold")
        self.assertIn("exception", exception["rationale"])
        self.assertEqual(narrowed["decision"], "hold")
        self.assertEqual(narrowed["simulation_outcome"], "unsupported")
        self.assertIn("Narrowing", narrowed["rationale"])
        self.assertEqual(stuck["decision"], "hold")
        self.assertFalse(result["world_unchanged"])
        self.assertFalse(result["scores_unchanged"])
        self.assertLess(result["final_counts"]["effective_grants"], result["initial_counts"]["effective_grants"])
        self.assertLess(result["final_counts"]["sensitive_excess_grants"], result["initial_counts"]["sensitive_excess_grants"])
        self.assertEqual(result["decisions"][0]["policy_version"], result["policy_version"])
        again = run_assessment(result["final_world"])
        self.assertEqual(again["applied_count"], 0)
        self.assertTrue(again["scores_unchanged"])
        self.assertTrue(again["world_unchanged"])
        self.assertIsNone(protected_reason({"in_workflow": False, "in_role": False, "in_exception": False, "last_used_days": 10, "requirement_class": "catalogued", "outcome": "remove", "removal_probe": {"safe_to_remove": True}}))
        self.assertIsNotNone(protected_reason({"in_workflow": True, "outcome": "retain", "severity": 0.9, "last_used_days": 200}))

    def test_scoring_failure_discards_the_copy(self) -> None:
        world = build_world()
        with self.assertRaises(RuntimeError):
            run_assessment(world, fail_phase="scoring")
        self.assertIn("perm-safe", next(row for row in world["identities"] if row["id"] == "EMP-1")["extra_permission_ids"])


class AssessmentApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.world = build_world()
        self.original = copy.deepcopy(self.world)
        self.analysis = analyze_world(self.world)
        self.metrics = {"_provenance": provenance(self.world), "labeled_cases": 1, "systems": {"full": {"f1": 0.5}}}
        self.ledger = Path(self.temp.name) / "ledger.sqlite"
        self.app = create_app(world=self.world, analysis=self.analysis, metrics=self.metrics, db_path=self.ledger)
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.app.state.assessment_fail = None
        self.app.state.assessment_block = None

    def tearDown(self) -> None:
        blocker = getattr(self.app.state, "assessment_block", None)
        if blocker is not None:
            blocker.set()
        self.app.state.assessment_fail = None
        self.client.__exit__(None, None, None)
        self.temp.cleanup()

    def permissions(self, identity_id: str) -> set[str]:
        body = self.client.get(f"/api/identities/{identity_id}").json()
        return {row["permission_id"] for row in body["identity"]["permissions"]}

    def wait(self, key: str) -> dict:
        started = self.client.post("/api/assessments", json={"idempotency_key": key})
        self.assertIn(started.status_code, {200, 202}, started.text)
        deadline = time.monotonic() + 20
        latest = started.json()
        while time.monotonic() < deadline:
            current = self.client.get("/api/assessments/current").json()
            latest = current["active"] or current["latest"] or latest
            if latest and latest["id"] == started.json()["id"] and latest["status"] not in {"queued", "running", "cancelling"}:
                return latest
            time.sleep(0.02)
        self.fail(f"assessment did not finish: {latest}")

    def test_refresh_persists_restarts_and_retries(self) -> None:
        done = self.wait("refresh-once-key")
        self.assertEqual(done["status"], "succeeded", done)
        self.assertGreater(done["summary"]["applied_count"], 0)
        self.assertFalse(done["summary"]["scores_unchanged"])
        self.assertEqual([row["status"] for row in done["phases"]], ["complete"] * 5)
        self.assertNotIn("perm-safe", self.permissions("EMP-1"))
        self.assertIn("perm-duty", self.permissions("EMP-1"))
        self.assertEqual(self.world, self.original)
        evaluation = self.client.get("/api/evaluation").json()
        self.assertEqual(evaluation["metrics"], {})
        self.assertIn("remediated copy", evaluation["evaluation_note"])
        self.assertEqual(evaluation["baseline_evaluation"]["status"], "unavailable")
        self.assertNotIn("f1", str(evaluation["baseline_evaluation"]))
        machine = self.client.get("/api/decisions?actor=machine&limit=200").json()
        self.assertGreater(machine["total"], 0)
        self.assertTrue(all(row["actor_type"] == "machine" and row["applied"] is False for row in machine["items"]))
        self.assertTrue(any(row["decision"] == "apply" and row["applied_in_simulation"] for row in machine["items"]))
        self.assertTrue(any(row["decision"] == "hold" and "workflow" in row["rationale"] for row in machine["items"]))
        self.assertEqual(self.client.get("/api/decisions?actor=human").json()["total"], 0)
        self.assertEqual(self.client.get("/api/decisions?decision=apply&limit=1").json()["items"][0]["decision"], "apply")
        recorded = self.client.get("/api/findings?review_status=recorded&limit=50").json()
        self.assertGreater(recorded["total"], 0)
        replay = self.client.post("/api/assessments", json={"idempotency_key": "refresh-once-key"})
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["id"], done["id"])
        self.assertEqual(self.client.get("/api/decisions?actor=machine&limit=1").json()["total"], machine["total"])
        dataset = self.client.get("/api/health").json()["dataset_id"]
        second = self.wait("refresh-again-key")
        self.assertEqual(second["status"], "succeeded", second)
        self.assertTrue(second["summary"]["scores_unchanged"])
        self.assertEqual(second["summary"]["applied_count"], 0)
        self.assertEqual(self.client.get("/api/health").json()["dataset_id"], dataset)
        simulation = self.client.post("/api/simulate", json={"identity_id": "EMP-1", "change": {"type": "remove_permission", "permission_id": "perm-duty"}}).json()
        accepted = self.client.post("/api/decisions", json={"simulation_id": simulation["simulation_id"], "decision": "accept", "analyst": "Demo student", "rationale": "This workflow grant should not be accepted.", "idempotency_key": "human-accept-1"})
        self.assertEqual(accepted.status_code, 409, accepted.text)
        deferred = self.client.post("/api/decisions", json={"simulation_id": simulation["simulation_id"], "decision": "defer", "analyst": "Demo student", "rationale": "The workflow still needs this permission.", "idempotency_key": "human-defer-key"})
        self.assertEqual(deferred.status_code, 200, deferred.text)
        self.assertFalse(deferred.json()["applied"])
        self.assertEqual(self.client.get("/api/decisions?actor=human").json()["total"], 1)
        self.assertEqual(self.client.get("/api/decisions?actor=machine&decision=defer").json()["total"], 0)
        self.client.__exit__(None, None, None)
        restored = create_app(world=self.world, analysis=self.analysis, metrics=self.metrics, db_path=self.ledger)
        with TestClient(restored) as client:
            self.assertEqual(client.get("/api/health").json()["dataset_id"], dataset)
            identity = client.get("/api/identities/EMP-1").json()
            self.assertNotIn("perm-safe", {row["permission_id"] for row in identity["identity"]["permissions"]})
            self.assertIn("perm-duty", {row["permission_id"] for row in identity["identity"]["permissions"]})
            self.assertGreaterEqual(client.get("/api/decisions?actor=machine&limit=1").json()["total"], machine["total"])
            self.assertEqual(client.get("/api/decisions?actor=human").json()["total"], 1)
            self.assertIn("remediated copy", client.get("/api/evaluation").json()["evaluation_note"])
            baseline = client.post("/api/run/activate", json={"job_id": None})
            self.assertEqual(baseline.status_code, 200, baseline.text)
            self.assertNotEqual(client.get("/api/health").json()["dataset_id"], dataset)
            self.assertIn("perm-safe", {row["permission_id"] for row in client.get("/api/identities/EMP-1").json()["identity"]["permissions"]})
            self.assertEqual(client.get("/api/evaluation").json()["metrics"]["labeled_cases"], 1)
            self.assertEqual(client.get("/api/decisions?actor=human").json()["total"], 1)
        self.client = TestClient(self.app)
        self.client.__enter__()

    def test_duplicate_cancel_stale_and_failed_runs_do_not_publish(self) -> None:
        self.app.state.assessment_block = threading.Event()
        first = self.client.post("/api/assessments", json={"idempotency_key": "blocked-run-key"})
        self.assertEqual(first.status_code, 202, first.text)
        self.assertEqual(self.client.post("/api/assessments", json={"idempotency_key": "blocked-run-key"}).json()["id"], first.json()["id"])
        busy = self.client.post("/api/assessments", json={"idempotency_key": "other-run-key1"})
        self.assertEqual(busy.status_code, 409, busy.text)
        self.assertEqual(self.client.post("/api/jobs", json={"command": "all", "seed": 7, "as_of": "2026-10-14"}).status_code, 409)
        cancelled = self.client.post(f"/api/assessments/{first.json()['id']}/cancel")
        self.assertEqual(cancelled.status_code, 200, cancelled.text)
        self.app.state.assessment_block.set()
        deadline = time.monotonic() + 20
        status = first.json()["status"]
        while time.monotonic() < deadline:
            status = self.client.get(f"/api/assessments/{first.json()['id']}").json()["status"]
            if status not in {"queued", "running", "cancelling"}:
                break
            time.sleep(0.02)
        self.assertEqual(status, "cancelled")
        self.assertEqual(self.client.get("/api/decisions").json()["total"], 0)
        self.assertIn("perm-safe", self.permissions("EMP-1"))
        self.app.state.assessment_block = threading.Event()
        stale = self.client.post("/api/assessments", json={"idempotency_key": "stale-run-key01"})
        self.assertEqual(stale.status_code, 202, stale.text)
        self.app.state.resources["epoch"] = 9
        self.app.state.assessment_block.set()
        deadline = time.monotonic() + 20
        stale_status = "running"
        while time.monotonic() < deadline:
            stale_status = self.client.get(f"/api/assessments/{stale.json()['id']}").json()["status"]
            if stale_status not in {"queued", "running", "cancelling"}:
                break
            time.sleep(0.02)
        self.assertEqual(stale_status, "stale")
        self.assertEqual(self.client.get("/api/decisions").json()["total"], 0)
        self.assertEqual(self.client.get("/api/health").json()["dataset_id"], self.app.state.resources["dataset_id"])
        self.app.state.assessment_fail = "scoring"
        failed = self.wait("failed-score-key")
        self.assertEqual(failed["status"], "failed", failed)
        self.assertIn("scoring", failed["error"])
        self.assertEqual(self.client.get("/api/decisions").json()["total"], 0)
        self.assertIn("perm-safe", self.permissions("EMP-1"))
        self.assertEqual(self.client.get("/api/evaluation").json()["metrics"]["labeled_cases"], 1)
        with tempfile.TemporaryDirectory() as folder:
            manager = RunManager(ROOT, Path(folder))
            try:
                with self.assertRaises(ValueError):
                    manager.start("assess", 7, "2026-10-14")
                with self.assertRaises(ValueError):
                    manager.reserve({"command": "generate", "idempotency_key": "not-a-real-key"})
            finally:
                manager.close()


if __name__ == "__main__":
    unittest.main()
