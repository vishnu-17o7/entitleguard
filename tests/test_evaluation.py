from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from entitleguard.artifacts import dataset_hash
from entitleguard.artifacts import validate_world
from entitleguard.evaluate import cluster_intervals
from entitleguard.evaluate import summarize_cases
from entitleguard.evaluate import evaluate
from entitleguard.pipeline import analyze_world
from entitleguard.behavior import fit_behavior
from entitleguard.policy import Directory
from entitleguard.generate import generate_enterprise
from entitleguard.holdout import evaluate_holdout


class EvaluationTests(unittest.TestCase):
    def test_hand_computed_metrics(self) -> None:
        rows = [{"identity_id": f"i{index}", "expected": actual, "predicted": predicted} for index, (actual, predicted) in enumerate([("retain", "remove"), ("temporary", "reduce"), ("review", "remove"), ("remove", "remove"), ("reduce", "retain")])]
        result = summarize_cases(rows)
        self.assertEqual((result["tp"], result["fp"], result["fn"]), (1, 3, 1))
        self.assertEqual(result["false_removals"], 1)
        self.assertEqual(result["unresolved_removals"], 1)
        self.assertEqual(result["harmful_reductions"], 1)
        self.assertEqual(result["false_removal_rate"], 0.5)
        self.assertEqual(result["confusion_matrix"]["temporary"]["reduce"], 1)
        self.assertEqual(cluster_intervals(rows), cluster_intervals(rows))

    def test_deterministic_and_varied(self) -> None:
        first = generate_enterprise(42)
        self.assertEqual(first, generate_enterprise(42))
        second = generate_enterprise(43)
        self.assertNotEqual(dataset_hash(first), dataset_hash(second))
        self.assertNotEqual(first["labels"], second["labels"])
        self.assertEqual(first["meta"]["splits"], second["meta"]["splits"])
        validate_world(first)
        self.assertEqual(first["meta"]["population"], {"employee": 490, "contractor": 10, "service": 75})

    def test_split_manifests_disjoint(self) -> None:
        world = generate_enterprise()
        splits = world["meta"]["splits"]
        self.assertTrue(all(splits.values()))
        self.assertEqual(sum(map(len, splits.values())), len(world["identities"]))
        self.assertFalse(set(splits["train"]) & set(splits["test"]))
        self.assertFalse(set(splits["validation"]) & set(splits["test"]))
        world["meta"]["splits"]["test"].append(splits["train"][0])
        with self.assertRaises(ValueError):
            validate_world(world)

    def test_predictions_reproduce_and_fit_does_not_use_test(self) -> None:
        import copy

        world = generate_enterprise()
        first = analyze_world(world)
        second = analyze_world(world)
        decisions = lambda analysis: [(owner, row["permission_id"], row["outcome"], row["necessity"], row["severity"]) for owner, record in analysis["identities"].items() for row in record["permissions"]]
        self.assertEqual(decisions(first), decisions(second))
        first_metrics = evaluate(world, first)
        second_metrics = evaluate(world, second)
        self.assertEqual(first_metrics["predictions"], second_metrics["predictions"])
        self.assertEqual(first_metrics["systems"], second_metrics["systems"])
        self.assertGreater(first_metrics["systems"]["full"]["confusion_matrix"]["reduce"]["reduce"], 0)
        modified = copy.deepcopy(world)
        test_ids = set(world["meta"]["splits"]["test"])
        for usage in modified["usage"]:
            if usage["identity_id"] in test_ids:
                usage["last_used_days"] = 999
        behavior = fit_behavior(Directory(modified))
        self.assertEqual(first["behavior"]["threshold"], behavior["threshold"])
        self.assertEqual(first["behavior"]["prevalence"], behavior["prevalence"])
        self.assertEqual({key: first["behavior"]["scores"][key] for key in world["meta"]["splits"]["train"]}, {key: behavior["scores"][key] for key in world["meta"]["splits"]["train"]})

    def test_independent_handwritten_holdout(self) -> None:
        result = evaluate_holdout()
        self.assertEqual(result["correct"], result["n"], result)


if __name__ == "__main__":
    unittest.main()
