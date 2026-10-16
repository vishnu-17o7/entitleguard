from __future__ import annotations

import csv
import io
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from entitleguard.artifacts import atomic_write
from entitleguard.artifacts import compatible
from entitleguard.artifacts import compatible_robustness
from entitleguard.artifacts import load_robustness
from entitleguard.artifacts import validate_world
from entitleguard.artifacts import provenance
from entitleguard.artifacts import read_json
from entitleguard.generate import generate_enterprise
from entitleguard.report import export_bundle
from entitleguard.report import load_original_benchmark
from entitleguard.report import safe_csv_cell


class ArtifactTests(unittest.TestCase):
    def test_atomic_and_invalidation(self) -> None:
        world = generate_enterprise()
        payload = {"_provenance": provenance(world), "value": "complete"}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "artifact.json"
            atomic_write(path, payload)
            self.assertEqual(read_json(path), payload)
            self.assertEqual(len(list(Path(folder).iterdir())), 1)
        self.assertTrue(compatible(payload, world))
        self.assertFalse(compatible({}, world))
        world["meta"]["seed"] += 1
        self.assertFalse(compatible(payload, world))

    def test_dangling_sources_rejected(self) -> None:
        import copy

        world = generate_enterprise()
        mutations = (
            lambda item: item["roles"][0]["grant_permission_ids"].append("missing"),
            lambda item: item["identities"][0]["direct_role_ids"].append("missing"),
            lambda item: item["identities"][0]["temporary_grants"].append({"permission_id": "missing"}),
            lambda item: item["workflows"][0]["required_permission_ids"].append("missing"),
        )
        for mutation in mutations:
            modified = copy.deepcopy(world)
            mutation(modified)
            with self.assertRaises(ValueError):
                validate_world(modified)

    def test_robustness_matching_member_and_stale_rejection(self) -> None:
        first = generate_enterprise(44, "2026-10-15")
        second = generate_enterprise(45, "2026-10-15")
        payload = {"_provenance": provenance(first), "as_of": "2026-10-15", "runs": [{"seed": 44, "dataset_id": provenance(first)["dataset_id"]}, {"seed": 45, "dataset_id": provenance(second)["dataset_id"]}]}
        self.assertTrue(compatible_robustness(payload, first))
        self.assertTrue(compatible_robustness(payload, second))
        self.assertFalse(compatible_robustness(payload, generate_enterprise(46, "2026-10-15")))
        self.assertFalse(compatible_robustness(payload, generate_enterprise(44)))
        with tempfile.TemporaryDirectory() as folder:
            atomic_write(Path(folder) / "robustness.json", payload)
            self.assertEqual(load_robustness(second, Path(folder)), payload)
        payload["_provenance"]["implementation_hash"] = "stale"
        self.assertFalse(compatible_robustness(payload, first))

    def test_original_benchmark_matches_only_its_dataset(self) -> None:
        loaded, robustness = load_original_benchmark({"original_dataset_id": "ee2ddce3ea5debb25fc3dc54763248a0417bbdb2986b93ef027694347fee7c39"})
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["labeled_cases"], 128)
        self.assertEqual(loaded["systems"]["full"]["false_removals"], 0)
        self.assertIsNotNone(robustness)
        labeled, _robustness = load_original_benchmark({"dataset_id": "synthetic-ee2ddce3ea5debb2", "original_dataset_id": "not-the-baseline"})
        self.assertEqual(labeled["labeled_cases"], 128)
        self.assertEqual(load_original_benchmark({}), (None, None))
        self.assertEqual(load_original_benchmark({"original_dataset_id": "not-a-dataset"}), (None, None))

    def test_safe_exports(self) -> None:
        world = generate_enterprise()
        analysis = {"_provenance": provenance(world)}
        metrics = {"labeled_cases": 1, "systems": {}, "predictions": [{"identity_id": "=cmd()", "permission_id": "<script>", "expected": "retain", "predicted": "remove"}], "limitations": ["<script>alert(1)</script>"]}
        exported = export_bundle(world, analysis, metrics, "csv")
        rows = list(csv.reader(io.StringIO(exported)))
        self.assertEqual(rows[1][1], "'=cmd()")
        report = export_bundle(world, analysis, metrics, "html")
        self.assertNotIn("<script>", report)
        self.assertIn("&lt;script&gt;", report)
        self.assertIn("dataset_hash", export_bundle(world, analysis, metrics))
        self.assertEqual(safe_csv_cell("  +SUM(A1)"), "'  +SUM(A1)")
        with self.assertRaises(ValueError):
            export_bundle(world, analysis, metrics, "xml")


if __name__ == "__main__":
    unittest.main()
