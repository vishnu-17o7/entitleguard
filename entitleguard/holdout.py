"""Handwritten policy-context regression cases independent of the generator."""
from __future__ import annotations


def holdout_cases() -> list[dict]:
    """Fixed predeclared expectations; these are regression fixtures, not training."""
    base = {"in_role": False, "in_workflow": False, "in_exception": False, "requirement_class": "documented", "last_used_days": 140, "jev": {"answers": {"role_consistency": {"noul": 0.05}}}, "peer_prevalence": 0.0, "narrowable": False, "removal_probe": {"broken_workflows": []}, "sensitivity": "high", "on_role_document": False}
    return [
        {"id": "documented-duty-old-log", "expected": "retain", "row": {**base, "in_role": True, "on_role_document": True}},
        {"id": "rare-recovery-duty", "expected": "retain", "row": {**base, "in_workflow": True, "removal_probe": {"broken_workflows": ["restore"]}}},
        {"id": "unrelated-sensitive-stale", "expected": "remove", "row": dict(base)},
        {"id": "missing-evidence", "expected": "review", "row": {**base, "last_used_days": None}},
        {"id": "known-narrower-scope", "expected": "reduce", "row": {**base, "narrowable": True}},
        {"id": "approved-exception", "expected": "temporary", "row": {**base, "in_exception": True}},
    ]


def evaluate_holdout() -> dict:
    """Report every fixture including errors; never tune against these cases."""
    from entitleguard.evaluate import predict

    cases = []
    for fixture in holdout_cases():
        predicted = predict("full", fixture["row"], status="active", anomaly=0.0, threshold=0.9)
        cases.append({"case_id": fixture["id"], "expected": fixture["expected"], "predicted": predicted, "correct": predicted == fixture["expected"]})
    return {"kind": "independent handwritten regression fixtures", "n": len(cases), "correct": sum(row["correct"] for row in cases), "cases": cases, "limitation": "Small deterministic context fixtures, not an independent population accuracy estimate."}
