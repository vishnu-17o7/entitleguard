"""API invariants use isolated temporary ledgers and no external providers."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from api import create_app
from entitleguard.generate import generate_enterprise
from entitleguard.pipeline import analyze_world


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.world = generate_enterprise()
        cls.analysis = analyze_world(cls.world)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app(world=self.world, analysis=self.analysis, metrics={}, db_path=Path(self.temp.name) / "ledger.sqlite")
        self.client = TestClient(self.app)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.temp.cleanup()

    def simulation(self) -> dict:
        response = self.client.post("/api/simulate", json={"identity_id": "EMP-104", "change": {"type": "remove_group", "group_id": "grp-data-engineer"}})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def decision(self, simulation_id: str) -> dict:
        return {"simulation_id": simulation_id, "decision": "accept", "analyst": "Demo student", "rationale": "Verified the current workflows remain available.", "idempotency_key": "demo-request-123"}

    def test_validation_and_legacy_write(self) -> None:
        for change in ({"type": "remove_permission", "permission_id": "missing"}, {"type": "remove_group", "group_id": "missing"}, {"type": "remove_permission", "permission_id": "missing", "unexpected": True}):
            self.assertEqual(self.client.post("/api/simulate", json={"identity_id": "EMP-104", "change": change}).status_code, 422)
        self.assertEqual(self.client.post("/api/approvals", json={}).status_code, 410)
        self.assertEqual(self.client.get("/api/identities?limit=0").status_code, 422)
        self.assertEqual(self.client.get("/api/identities/missing").status_code, 404)
        self.assertEqual(self.client.post("/api/simulate", headers={"Origin": "https://evil.example"}, json={}).status_code, 403)

    def test_pagination_has_no_silent_cap(self) -> None:
        first = self.client.get("/api/identities?limit=30").json()
        second = self.client.get("/api/identities?limit=30&offset=30").json()
        self.assertEqual(first["total"], len(self.world["identities"]))
        self.assertFalse({r["id"] for r in first["items"]} & {r["id"] for r in second["items"]})
        self.assertEqual(len(second["items"]), 30)

    def test_decision_is_idempotent_and_persistent(self) -> None:
        simulation = self.simulation()
        body = self.decision(simulation["simulation_id"])
        first = self.client.post("/api/decisions", json=body)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json(), self.client.post("/api/decisions", json=body).json())
        self.assertFalse(first.json()["applied"])
        self.assertEqual(self.client.get("/api/decisions").json()["total"], 1)
        body["decision"] = "defer"
        self.assertEqual(self.client.post("/api/decisions", json=body).status_code, 409)
        from entitleguard.storage import Ledger
        self.assertEqual(len(Ledger(Path(self.temp.name) / "ledger.sqlite").decisions()), 1)

    def test_stale_simulation_rejected(self) -> None:
        simulation = self.simulation()
        self.app.state.resources["snapshot_version"] = "new-version"
        self.assertEqual(self.client.post("/api/decisions", json=self.decision(simulation["simulation_id"])).status_code, 409)

    def test_unsafe_accept_rejected_but_defer_allowed(self) -> None:
        from entitleguard.catalog import P_PAY_RESTORE
        result = self.client.post("/api/simulate", json={"identity_id": "EMP-027", "change": {"type": "remove_permission", "permission_id": P_PAY_RESTORE}}).json()
        body = self.decision(result["simulation_id"])
        self.assertEqual(self.client.post("/api/decisions", json=body).status_code, 409)
        body["decision"] = "defer"
        self.assertEqual(self.client.post("/api/decisions", json=body).status_code, 200)

    def test_concurrent_retries_share_one_transactional_record(self) -> None:
        from concurrent.futures import ThreadPoolExecutor
        simulation = self.simulation()
        body = self.decision(simulation["simulation_id"])
        state = self.app.state.resources
        names = {r["id"]: r["name"] for r in self.world["identities"]}
        def record_one(_: int) -> dict:
            return state["store"].decide(body, state["dataset_id"], names, state["snapshot_version"])
        with ThreadPoolExecutor(max_workers=4) as pool:
            records = list(pool.map(record_one, range(8)))
        self.assertEqual(len({r["id"] for r in records}), 1)
        self.assertEqual(len(state["store"].decisions()), 1)

    def test_activation_rejects_request_with_captured_old_state(self) -> None:
        from api import resources
        simulation = self.simulation()
        old_state = self.app.state.resources
        self.app.state.resources = {**old_state}
        self.app.dependency_overrides[resources] = lambda: old_state
        response = self.client.post("/api/decisions", json=self.decision(simulation["simulation_id"]))
        self.assertEqual(response.status_code, 409, response.text)
        self.assertIn("active run changed", response.text)
        self.assertEqual(old_state["store"].decisions(), [])
        self.app.dependency_overrides.clear()

    def test_decision_commit_holds_run_activation_lock(self) -> None:
        from unittest.mock import patch
        simulation = self.simulation()
        state = self.app.state.resources
        manager = self.app.state.run_manager
        original = state["store"].decide
        observed: list[bool] = []
        def checked_commit(*args: object) -> dict:
            acquired = manager.activation_lock.acquire(blocking=False)
            observed.append(acquired)
            if acquired:
                manager.activation_lock.release()
            return original(*args)
        with patch.object(state["store"], "decide", side_effect=checked_commit):
            response = self.client.post("/api/decisions", json=self.decision(simulation["simulation_id"]))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(observed, [False])

    def test_missing_compatible_metrics_returns_reviewable_export_error(self) -> None:
        response = self.client.get("/api/export?format=html")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"]["code"], "evaluation_unavailable")
        self.assertIn("robustness", self.client.get("/api/evaluation").json())

    def test_remediated_export_uses_the_saved_original_benchmark(self) -> None:
        from unittest.mock import patch
        metrics = {"_provenance": {"dataset_id": "synthetic-original", "dataset_hash": "abc"}, "labeled_cases": 2, "systems": {"full": {"precision": 1, "recall": 1, "f1": 1, "false_removals": 0, "unresolved_removals": 0, "harmful_reductions": 0, "workflow_preservation": 1}}, "predictions": [], "limitations": ["Synthetic laboratory labels."]}
        state = self.app.state.resources
        state["metrics"] = {}
        state["run"]["evaluation_status"] = "unavailable"
        state["run"]["evaluation_note"] = "This snapshot is a remediated copy of the evidence."
        state["assessment"] = {"original_dataset_id": "abc", "applied_count": 81, "held_count": 402, "initial_counts": {"sensitive_excess_grants": 73}, "final_counts": {"sensitive_excess_grants": 19}, "baseline_evaluation": {"status": "unavailable", "dataset_id": "synthetic-original"}}
        with patch("entitleguard.report.load_original_benchmark", return_value=(metrics, {"runs": []})) as loader:
            exported = self.client.get("/api/export?format=html")
            evaluation = self.client.get("/api/evaluation")
        self.assertEqual(exported.status_code, 200, exported.text)
        self.assertIn("Original benchmark", exported.text)
        self.assertIn("73 to 19", exported.text)
        self.assertNotIn("evaluation_unavailable", exported.text)
        self.assertEqual(evaluation.status_code, 200)
        body = evaluation.json()
        self.assertEqual(body["metrics"], {})
        self.assertEqual(body["benchmark"]["labeled_cases"], 2)
        self.assertEqual(loader.call_count, 2)

    def test_legacy_rows_survive_migration_with_unknown_provenance(self) -> None:
        from entitleguard.storage import Ledger
        store = self.app.state.resources["store"]
        with store.connection() as db:
            db.execute("INSERT INTO approvals (identity_id,permission_id,outcome,analyst,created_at) VALUES (?,?,?,?,?)", ("historical", "unknown", "old-outcome", "old analyst", "2025-01-01"))
        reopened = Ledger(store.path)
        rows = reopened.legacy()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["outcome"], "old-outcome")
        self.assertTrue(rows[0]["legacy"])
        self.assertFalse(rows[0]["applied"])

    def test_noop_simulation_is_persisted_with_unique_id_and_not_accepted(self) -> None:
        request = {"identity_id": "EMP-104", "change": {"type": "revoke_expired_temporary"}}
        first = self.client.post("/api/simulate", json=request).json()
        second = self.client.post("/api/simulate", json=request).json()
        self.assertEqual(first["verdict"], "no_change")
        self.assertNotEqual(first["simulation_id"], second["simulation_id"])
        self.assertEqual(self.client.post("/api/decisions", json=self.decision(first["simulation_id"])).status_code, 409)

    def test_findings_sort_filter_before_pagination(self) -> None:
        all_rows = self.analysis["findings"]
        expected = sorted(all_rows, key=lambda row: (row["name"].casefold(), row["identity_id"], row["permission_id"]))
        result = self.client.get("/api/findings?sort=name&limit=5&offset=7").json()
        self.assertEqual([(r["identity_id"], r["permission_id"]) for r in result["items"]], [(r["identity_id"], r["permission_id"]) for r in expected[7:12]])
        for band, check in (("high", lambda value: value >= 0.7), ("medium", lambda value: 0.4 <= value < 0.7), ("low", lambda value: value < 0.4)):
            response = self.client.get(f"/api/findings?severity={band}&limit=5").json()
            self.assertEqual(response["total"], sum(check(row["severity"]) for row in all_rows))
            self.assertTrue(all(check(row["severity"]) for row in response["items"]))
        missing = self.client.get("/api/findings?evidence=missing&limit=3").json()
        complete = self.client.get("/api/findings?evidence=complete&limit=3").json()
        self.assertEqual(missing["total"] + complete["total"], len(all_rows))
        self.assertTrue(all(not row["evidence_complete"] for row in missing["items"]))
        self.assertTrue(all(row["evidence_complete"] for row in complete["items"]))
        for query in ("sort=invalid", "evidence=invalid", "review_status=invalid", "severity=unknown", "severity=nan", "severity=2", "decision=remove"):
            endpoint = "decisions" if query.startswith("decision=") else "findings"
            self.assertEqual(self.client.get(f"/api/{endpoint}?{query}").status_code, 422)

    def test_decision_filter_and_findings_review_status(self) -> None:
        simulation = self.simulation()
        body = self.decision(simulation["simulation_id"])
        self.assertEqual(self.client.post("/api/decisions", json=body).status_code, 200)
        second = {**body, "decision": "defer", "idempotency_key": "another-demo-key"}
        self.assertEqual(self.client.post("/api/decisions", json=second).status_code, 200)
        result = self.client.get("/api/decisions?decision=defer&limit=1").json()
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["decision"], "defer")
        self.assertEqual(self.client.get("/api/decisions?decision=reject").json()["total"], 0)
        recorded = self.client.get("/api/findings?review_status=recorded&limit=200").json()
        self.assertGreater(recorded["total"], 0)
        self.assertTrue(all(row["identity_id"] == "EMP-104" and row["review_status"] == "recorded" for row in recorded["items"]))
        unrecorded = self.client.get("/api/findings?review_status=unrecorded").json()
        self.assertEqual(recorded["total"] + unrecorded["total"], len(self.analysis["findings"]))


if __name__ == "__main__":
    unittest.main()
