"""Policy, drift, simulation, and the two demonstration cases."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from entitleguard.catalog import P_BILLING_UPDATE, P_CUST_SECRET, P_DATA_S3_DELETE, P_DATA_WH_WRITE, P_ML_TRAIN, P_PAY_RESTORE  # noqa: E402
from entitleguard.drift import drift_ratio  # noqa: E402
from entitleguard.evaluate import predict  # noqa: E402
from entitleguard.generate import generate_enterprise  # noqa: E402
from entitleguard.pipeline import analyze_world  # noqa: E402
from entitleguard.policy import Directory  # noqa: E402
from entitleguard.simulate import simulate  # noqa: E402


class EntitleGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.world = generate_enterprise()
        cls.directory = Directory(cls.world)

    def test_scale(self) -> None:
        meta = self.world["meta"]
        self.assertEqual(meta["employees"], 500)
        self.assertEqual(meta["service_accounts"], 75)
        self.assertEqual(meta["departments"], 8)
        self.assertEqual(meta["job_roles"], 30)
        self.assertEqual(meta["resources"], 200)
        self.assertEqual(len(self.world["permissions"]), 150)

    def test_explicit_deny_wins(self) -> None:
        identity = self.directory.identity("EMP-001")
        granted, _sources = self.directory.effective(identity)
        self.assertTrue(granted)
        denied = next(iter(granted))
        clone = {**identity, "deny_permission_ids": [denied]}
        after, _sources = self.directory.effective(clone)
        self.assertNotIn(denied, after)

    def test_drift_formula(self) -> None:
        self.assertEqual(drift_ratio({"a", "b", "c", "d"}, {"a"}), 0.75)
        self.assertEqual(drift_ratio(set(), {"a"}), 0.0)

    def test_role_transfer_keeps_legacy_database(self) -> None:
        identity = self.directory.identity("EMP-104")
        granted, _sources = self.directory.effective(identity)
        self.assertIn(P_DATA_WH_WRITE, granted)
        self.assertIn(P_ML_TRAIN, granted)
        result = simulate(
            self.directory,
            "EMP-104",
            {"type": "remove_group", "group_id": "grp-data-engineer"},
        )
        self.assertIn(P_DATA_WH_WRITE, result["removed_permission_ids"])
        self.assertNotIn(P_ML_TRAIN, result["removed_permission_ids"])
        self.assertTrue(result["safe_to_remove"])
        names = " ".join(row["name"] + row["after"] for row in result["workflows"])
        self.assertIn("allowed", names)
        self.assertNotIn("broken", "".join(row["after"] for row in result["workflows"]))

    def test_quarterly_restore_is_not_safe_to_drop(self) -> None:
        identity = self.directory.identity("EMP-027")
        granted, _sources = self.directory.effective(identity)
        self.assertIn(P_PAY_RESTORE, granted)
        result = simulate(
            self.directory,
            "EMP-027",
            {"type": "remove_permission", "permission_id": P_PAY_RESTORE},
        )
        self.assertFalse(result["safe_to_remove"])
        self.assertTrue(result["broken_workflows"])

    def test_demo_recommendations(self) -> None:
        analysis = analyze_world(self.world)
        maya = analysis["identities"]["EMP-104"]
        write = next(row for row in maya["permissions"] if row["permission_id"] == P_DATA_WH_WRITE)
        train = next(row for row in maya["permissions"] if row["permission_id"] == P_ML_TRAIN)
        self.assertEqual(write["outcome"], "remove")
        self.assertEqual(train["outcome"], "retain")
        self.assertTrue(any(item["change"].get("group_id") == "grp-data-engineer" for item in maya["proposals"]))
        arun = analysis["identities"]["EMP-027"]
        restore = next(row for row in arun["permissions"] if row["permission_id"] == P_PAY_RESTORE)
        self.assertEqual(restore["outcome"], "retain")
        self.assertEqual(
            predict("unused_90", restore, status="active", anomaly=0.0, threshold=0.9),
            "remove",
        )
        narrowed = next(
            row
            for record in analysis["identities"].values()
            for row in record["permissions"]
            if row["permission_id"] == P_DATA_S3_DELETE and record["scenarios"] == ["excess_scope"]
        )
        self.assertEqual(narrowed["outcome"], "reduce")
        secret = next(row for row in analysis["identities"]["SVC-018"]["permissions"] if row["permission_id"] == P_CUST_SECRET)
        self.assertEqual(secret["outcome"], "remove")
        exception = next(
            row
            for record in analysis["identities"].values()
            for row in record["permissions"]
            if "approved_exception" in record["scenarios"] and row["permission_id"] == P_BILLING_UPDATE
        )
        self.assertFalse(exception["in_role"])
        self.assertTrue(exception["in_exception"])
        self.assertEqual(exception["outcome"], "temporary")

    def test_missing_usage_is_not_proof(self) -> None:
        identity = next(
            row for row in self.world["identities"] if "missing_usage" in row["scenarios"]
        )
        result = simulate(
            self.directory,
            identity["id"],
            {"type": "remove_permission", "permission_id": identity["extra_permission_ids"][0]},
        )
        self.assertTrue(result["missing_usage"])
        self.assertFalse(result["safe_to_remove"])


if __name__ == "__main__":
    unittest.main()
