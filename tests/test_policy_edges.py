"""Independent source-path, temporal exception, and provider validation fixtures."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from entitleguard.generate import generate_enterprise
from entitleguard.graph import graph_payload
from entitleguard.jev import JevClient
from entitleguard.jev import build_state
from entitleguard.policy import Directory
from entitleguard.simulate import simulate


class PolicyEdges(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.world = generate_enterprise()

    def test_permission_path_does_not_borrow_different_direct_grant(self) -> None:
        world = copy.deepcopy(self.world)
        directory = Directory(world)
        identity = directory.identity("EMP-104")
        from entitleguard.catalog import P_DATA_WH_WRITE
        permission = directory.permissions[P_DATA_WH_WRITE]
        other = "fixture-other-permission"
        directory.permissions[other] = {**permission, "id": other, "action": "db:Read"}
        identity["extra_permission_ids"].append(other)
        paths = [p for p in graph_payload(directory, identity)["paths"] if p["permission_id"] == P_DATA_WH_WRITE]
        self.assertTrue(paths)
        self.assertTrue(all(len(p["path"]) >= 3 for p in paths))
        self.assertTrue(all(p["source"]["type"] != "direct" for p in paths))
        identity["deny_permission_ids"].append(P_DATA_WH_WRITE)
        denied = [p for p in graph_payload(directory, identity)["paths"] if p["permission_id"] == P_DATA_WH_WRITE]
        self.assertTrue(all(p["denied"] and not p["effective"] for p in denied))

    def test_redundant_source_is_preserved_and_noop_is_explicit(self) -> None:
        directory = Directory(copy.deepcopy(self.world))
        identity = directory.identity("EMP-104")
        role_id = directory.groups["grp-data-engineer"]["role_ids"][0]
        identity["direct_role_ids"].append(role_id)
        result = simulate(directory, identity["id"], {"type": "remove_group", "group_id": "grp-data-engineer"})
        self.assertEqual(result["verdict"], "no_change")
        self.assertFalse(result["safe_to_remove"])
        self.assertEqual(result["removed_permission_ids"], [])
        self.assertIn("grp-data-engineer", identity["group_ids"])

    def test_exception_inclusive_date_boundaries(self) -> None:
        directory = Directory(copy.deepcopy(self.world))
        identity = directory.identity("EMP-104")
        directory.exceptions = [{"identity_id": identity["id"], "permission_id": "fixture", "active": True, "effective_on": "2026-01-02", "expires_on": "2026-01-04"}]
        self.assertEqual(directory.exception_needs(identity, "2026-01-01"), set())
        self.assertEqual(directory.exception_needs(identity, "2026-01-02"), {"fixture"})
        self.assertEqual(directory.exception_needs(identity, "2026-01-04"), {"fixture"})
        self.assertEqual(directory.exception_needs(identity, "2026-01-05"), set())

    def test_empty_ai_response_falls_back_without_fabricated_certainty(self) -> None:
        context = build_state(role_title="ML Engineer", team="ML", responsibility="Train models", action="db:Write", resource_name="warehouse", sensitivity="critical", last_used_days=100, approved_exception=False, in_documented_duties=False, workflow_cadence=None)
        response = MagicMock()
        response.json.return_value = {"model": "typesafe/jev-1.13", "schema_version": "entitle-q-v1", "answers": {}}
        with patch("entitleguard.jev.httpx.Client") as mocked:
            mocked.return_value.__enter__.return_value.post.return_value = response
            result = JevClient(provider="openrouter").judge(context)
        self.assertEqual(result["provider"], "heuristic-fallback")
        self.assertEqual(result["error"], "ValueError")
        self.assertIn("Missing", result["fallback_reason"])
        self.assertLess(result["answers"]["review_priority"]["confidence"], 1)

    def test_provider_schema_probabilities_and_failures(self) -> None:
        from config import JEV_OPENROUTER_MODEL
        from config import JEV_SCHEMA_VERSION
        import httpx
        context = build_state(role_title="Engineer", team="ML", responsibility="Train models", action="db:Write", resource_name="warehouse", sensitivity="critical", last_used_days=100, approved_exception=False, in_documented_duties=False, workflow_cadence=None)
        valid = {"model": JEV_OPENROUTER_MODEL, "schema_version": JEV_SCHEMA_VERSION, "answers": {
            "role_consistency": {"type": "noul", "noul": 0.2},
            "rare_usage_plausible": {"type": "noul", "noul": 0.3},
            "review_priority": {"type": "choice", "choice": "urgent", "probabilities": {"standard": 0.1, "investigate": 0.2, "urgent": 0.7}}}}
        payloads = [valid]
        for field, value in (("role_consistency", float("nan")), ("rare_usage_plausible", -0.1)):
            malformed = copy.deepcopy(valid)
            malformed["answers"][field]["noul"] = value
            payloads.append(malformed)
        malformed = copy.deepcopy(valid)
        malformed["answers"]["review_priority"]["probabilities"]["urgent"] = 0.1
        payloads.append(malformed)
        malformed = copy.deepcopy(valid)
        malformed["answers"]["review_priority"]["choice"] = "invalid"
        payloads.append(malformed)
        for index, payload in enumerate(payloads):
            response = MagicMock()
            response.json.return_value = payload
            with patch("entitleguard.jev.httpx.Client") as mocked:
                mocked.return_value.__enter__.return_value.post.return_value = response
                judgment = JevClient(provider="openrouter").judge(context)
            self.assertEqual(judgment["provider"], "openrouter" if index == 0 else "heuristic-fallback")
        for failure in (httpx.ReadTimeout("timed out"), httpx.HTTPStatusError("rate limited", request=httpx.Request("POST", "https://example.test"), response=httpx.Response(429))):
            with patch("entitleguard.jev.httpx.Client") as mocked:
                mocked.return_value.__enter__.return_value.post.side_effect = failure
                judgment = JevClient(provider="openrouter").judge(context)
            self.assertEqual(judgment["provider"], "heuristic-fallback")
            self.assertTrue(judgment["fallback_reason"])


if __name__ == "__main__":
    unittest.main()
