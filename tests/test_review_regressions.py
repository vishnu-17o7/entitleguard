"""Source-specific proposals and test-population timing contracts."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from entitleguard.artifacts import validate_world
from entitleguard.evaluate import evaluate
from entitleguard.generate import generate_enterprise
from entitleguard.pipeline import analyze_world
from entitleguard.policy import Directory


class ReviewRegressions(unittest.TestCase):
    def test_direct_grant_proposals_preserve_other_sources_and_denies(self) -> None:
        world = generate_enterprise()
        denied_identity = next(row for row in world["identities"] if row["extra_permission_ids"])
        denied = denied_identity["extra_permission_ids"][0]
        denied_identity["deny_permission_ids"].append(denied)
        redundant_identity = next(row for row in world["identities"] if row["id"] != denied_identity["id"] and row["group_ids"])
        directory = Directory(world)
        redundant = next(iter(directory.effective(redundant_identity)[0]))
        redundant_identity["extra_permission_ids"].append(redundant)
        validate_world(world)

        analysis = analyze_world(world)
        for identity, permission_id in ((denied_identity, denied), (redundant_identity, redundant)):
            proposal = next(row for row in analysis["identities"][identity["id"]]["proposals"] if row["id"] == f"perm:{permission_id}")
            self.assertEqual(proposal["change"]["type"], "remove_direct_grant")
            self.assertEqual(proposal["simulation"]["verdict"], "no_change")
            self.assertEqual(proposal["simulation"]["removed_permission_ids"], [])
            self.assertFalse(proposal["simulation"]["safe_to_remove"])
            if permission_id == denied:
                self.assertNotIn(denied, proposal["simulation"]["retained_permission_ids"])
            else:
                self.assertIn(redundant, proposal["simulation"]["retained_permission_ids"])

    def test_latency_uses_evaluated_test_population(self) -> None:
        world = generate_enterprise()
        analysis = analyze_world(world)
        with patch("entitleguard.evaluate.time.perf_counter", side_effect=range(16)):
            metrics = evaluate(world, analysis)
        test_count = sum(row["split"] == "test" for row in world["identities"])
        self.assertLess(test_count, len(world["identities"]))
        self.assertEqual(metrics["latency_ms_per_identity"], round(8000 / test_count, 3))
        self.assertIn("all eight systems", metrics["metric_definitions"]["latency"])
        self.assertIn("test identity", metrics["metric_definitions"]["latency"])


if __name__ == "__main__":
    unittest.main()
