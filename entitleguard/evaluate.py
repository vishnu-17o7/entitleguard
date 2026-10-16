"""Compare EntitleGuard with usage, whitelist, isolation forest, and ablations."""
from __future__ import annotations

import time

from entitleguard.fusion import decide
from entitleguard.fusion import necessity
from entitleguard.policy import Directory

SYSTEMS = (
    "unused_90",
    "role_whitelist",
    "isolation_forest",
    "rules",
    "minus_jev",
    "minus_context",
    "minus_peers",
    "full",
)

POSITIVE = {"remove", "reduce"}
LEGITIMATE = {"retain", "review", "temporary"}


def _flags(system: str) -> dict[str, bool] | None:
    if system == "full":
        return {"use_jev": True, "use_peers": True, "use_context": True}
    if system == "rules":
        return {"use_jev": False, "use_peers": False, "use_context": True}
    if system == "minus_jev":
        return {"use_jev": False, "use_peers": True, "use_context": True}
    if system == "minus_context":
        return {"use_jev": False, "use_peers": False, "use_context": False}
    if system == "minus_peers":
        return {"use_jev": True, "use_peers": False, "use_context": True}
    return None


def predict(system: str, row: dict, *, status: str, anomaly: float, threshold: float) -> str:
    """Outcome for one grant under one system."""
    flags = _flags(system)
    if flags is not None:
        return decide(
            status=status,
            in_role=bool(row["in_role"]),
            in_workflow=bool(row["in_workflow"]),
            in_exception=bool(row["in_exception"]),
            requirement_class=str(row["requirement_class"]),
            last_used_days=row["last_used_days"],
            jev_consistency=float(row["jev"]["answers"]["role_consistency"]["noul"]),
            peer_prevalence=float(row["peer_prevalence"]),
            narrowable=bool(row["narrowable"]),
            sim_broken=bool(row["removal_probe"]["broken_workflows"]),
            sensitive=row["sensitivity"] in {"high", "critical"},
            **flags,
        )
    if system == "unused_90":
        last_used = row["last_used_days"]
        if last_used is None or last_used > 90:
            return "remove"
        return "retain"
    if system == "role_whitelist":
        if row["on_role_document"]:
            return "retain"
        return "remove"
    if system == "isolation_forest":
        if anomaly >= threshold and not row["on_role_document"] and float(row["peer_prevalence"]) < 0.5:
            return "remove"
        return "retain"
    raise KeyError(system)


def _necessity(system: str, outcome: str, row: dict) -> float:
    if system in {"unused_90", "role_whitelist", "isolation_forest"}:
        return 0.08 if outcome == "remove" else 0.9
    jev_p = float(row["jev"]["answers"]["role_consistency"]["noul"])
    documented = outcome in {"retain", "temporary"}
    return necessity(outcome, jev_p, documented)


def _prf(pairs: list[tuple[bool, bool]]) -> dict[str, float | int]:
    tp = sum(1 for y, pred in pairs if y and pred)
    fp = sum(1 for y, pred in pairs if not y and pred)
    fn = sum(1 for y, pred in pairs if y and not pred)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


OUTCOMES = ("retain", "remove", "reduce", "temporary", "review")
KNOWN_LEGITIMATE = {"retain", "temporary"}
LIMITATIONS = [
    "Role histories and event dates are fixed; changing as-of reevaluates the same assignments, not a newly generated historical organization.",
    "Synthetic labels and shared scenario templates do not establish real-world generalization.",
    "Offline heuristic scores are not calibrated probabilities; no live-model quality is measured.",
    "The full fusion does not consume Isolation Forest scores; that model is a separate baseline.",
    "minus_context and unused_90 intentionally share the inactivity rule; they are not independent evidence.",
    "Thresholds are fixed a priori or trained on training identities; validation is reserved and no test tuning is performed.",
    "Reduce is a recommendation requiring an explicit narrowing proposal; only remove is applied in workflow and grant-change metrics.",
    "Zero observed unsafe removals does not establish universal safety; grants within identities are correlated.",
]


def summarize_cases(cases: list[dict]) -> dict:
    """Hand-auditable outcomes with unresolved cases separated from known need."""
    confusion = {actual: {predicted: 0 for predicted in OUTCOMES} for actual in OUTCOMES}
    for case in cases:
        confusion[case["expected"]][case["predicted"]] += 1
    result = _prf([(row["expected"] in POSITIVE, row["predicted"] in POSITIVE) for row in cases])
    legitimate = sum(row["expected"] in KNOWN_LEGITIMATE for row in cases)
    false_removals = sum(row["expected"] in KNOWN_LEGITIMATE and row["predicted"] == "remove" for row in cases)
    unresolved = sum(row["expected"] == "review" for row in cases)
    unresolved_removals = sum(row["expected"] == "review" and row["predicted"] == "remove" for row in cases)
    harmful_reductions = sum(row["expected"] in KNOWN_LEGITIMATE and row["predicted"] == "reduce" for row in cases)
    return {**result, "confusion_matrix": confusion, "labeled_cases": len(cases), "false_removals": false_removals, "legitimate_cases": legitimate, "false_removal_rate": round(false_removals / legitimate, 4) if legitimate else None, "unresolved_cases": unresolved, "unresolved_removals": unresolved_removals, "harmful_reductions": harmful_reductions, "harmful_changes": false_removals + harmful_reductions, "review_load": round(sum(row["predicted"] == "review" for row in cases) / len(cases), 4) if cases else 0.0, "brier": None}


def cluster_intervals(cases: list[dict], repeats: int = 300, seed: int = 42) -> dict:
    """Percentile intervals resample identities, preserving correlated grant clusters."""
    import random

    import numpy as np

    buckets: dict[str, list[dict]] = {}
    for row in cases:
        buckets.setdefault(row["identity_id"], []).append(row)
    owners = sorted(buckets)
    if len(owners) < 2:
        return {"method": "identity-cluster percentile bootstrap", "clusters": len(owners), "replicates": 0, "intervals": {}, "note": "Insufficient independent identities"}
    rng = random.Random(seed)
    samples = {key: [] for key in ("precision", "recall", "f1", "false_removal_rate")}
    for _ in range(repeats):
        sample = [row for owner in rng.choices(owners, k=len(owners)) for row in buckets[owner]]
        metrics = summarize_cases(sample)
        for key in samples:
            if metrics[key] is not None:
                samples[key].append(metrics[key])
    return {"method": "identity-cluster percentile bootstrap", "confidence": 0.95, "clusters": len(owners), "replicates": repeats, "note": "Observed-support bootstrap can be degenerate at zero errors; it does not bound unseen failure probability.", "intervals": {key: [round(float(np.quantile(values, 0.025)), 4), round(float(np.quantile(values, 0.975)), 4)] for key, values in samples.items() if values}}


def evaluate(world: dict, analysis: dict) -> dict:
    """Evaluate only frozen test identities; keep predictions and metric definitions."""
    from entitleguard.holdout import evaluate_holdout
    from entitleguard.artifacts import provenance
    from entitleguard.artifacts import validate_world

    validate_world(world)
    directory = Directory(world)
    labels = {(row["identity_id"], row["permission_id"]): row for row in world["labels"]}
    threshold = float(analysis["behavior"]["threshold"])
    cases: list[dict] = []
    systems: dict[str, dict] = {}
    timing = {}
    scenarios: dict[str, dict] = {}
    evaluated_identities = sum(record["split"] == "test" for record in analysis["identities"].values())
    for system in SYSTEMS:
        started = time.perf_counter()
        predictions = {}
        selected = []
        for record in analysis["identities"].values():
            if record["split"] != "test":
                continue
            for row in record["permissions"]:
                key = (record["id"], row["permission_id"])
                outcome = predict(system, row, status=record["status"], anomaly=float(record["anomaly"]), threshold=threshold)
                predictions[key] = outcome
                if key in labels:
                    label = labels[key]
                    selected.append({"identity_id": key[0], "permission_id": key[1], "system": system, "expected": label["expected"], "predicted": outcome, "scenario": label["scenario"], "correct": outcome == label["expected"]})
        timing[system] = round((time.perf_counter() - started) * 1000, 3)
        metrics = summarize_cases(selected)
        kept = total = already_broken = 0
        sensitive_before = sensitive_after = 0
        resources_before: set[str] = set()
        resources_after: set[str] = set()
        for identity in world["identities"]:
            if identity["split"] != "test":
                continue
            before, _sources = directory.effective(identity)
            drop_ids = {pid for (owner, pid), outcome in predictions.items() if owner == identity["id"] and outcome == "remove"}
            after, _sources = directory.effective(identity, drop_permissions=drop_ids)
            for workflow in directory.workflows_for(identity):
                required = set(workflow["required_permission_ids"])
                if not required <= before:
                    already_broken += 1
                    continue
                total += 1
                kept += required <= after
            record = analysis["identities"][identity["id"]]
            for row in record["permissions"]:
                if row["excess"] and row["sensitivity"] in {"high", "critical"}:
                    sensitive_before += 1
                    resources_before.add(row["resource_id"])
                    if row["permission_id"] in after:
                        sensitive_after += 1
                        resources_after.add(row["resource_id"])
        metrics.update({"workflow_preservation": round(kept / total, 4) if total else None, "workflows": {"preserved": kept, "eligible_before": total, "already_broken": already_broken}, "sensitive_excess_grants": {"before": sensitive_before, "after": sensitive_after, "reduction": round((sensitive_before - sensitive_after) / sensitive_before, 4) if sensitive_before else 0.0}, "sensitive_excess_resources": {"before": len(resources_before), "after": len(resources_after)}, "confidence_intervals": cluster_intervals(selected)})
        # Compatibility alias, explicitly defined as grants rather than exploit paths.
        metrics["attack_paths"] = metrics["sensitive_excess_grants"]
        systems[system] = metrics
        cases.extend(selected)
        for scenario in sorted({row["scenario"] for row in selected}):
            rows = [row for row in selected if row["scenario"] == scenario]
            bucket = scenarios.setdefault(scenario, {"n": len(rows), "systems": {}, "errors": []})
            bucket["systems"][system] = summarize_cases(rows)
            bucket["errors"].extend(row for row in rows if not row["correct"])
            if system == "full":
                bucket["full_correct"] = sum(row["correct"] for row in rows)
                bucket["full_false_removals"] = metrics["false_removals"] if len(rows) == len(selected) else sum(row["expected"] in KNOWN_LEGITIMATE and row["predicted"] == "remove" for row in rows)
            if system == "unused_90":
                bucket["unused90_false_removals"] = sum(row["expected"] in KNOWN_LEGITIMATE and row["predicted"] == "remove" for row in rows)
    return {"independent_holdout": evaluate_holdout(), "_provenance": provenance(world), "split": "test", "labeled_cases": systems["full"]["labeled_cases"], "jev_mode": "heuristic", "note": "Frozen identity test split. Offline heuristic only; no live model calls.", "score_semantics": "Heuristic scores, not calibrated probabilities", "systems": systems, "scenarios": scenarios, "predictions": cases, "timings_ms": {"baseline_prediction_only": timing, "analysis": analysis.get("timings_ms", {})}, "latency_ms_per_identity": round(sum(timing.values()) / evaluated_identities, 3) if evaluated_identities else None, "limitations": LIMITATIONS, "metric_definitions": {"positive": "Expected/predicted remove or reduce", "false_removal": "Predicted remove on known retain/temporary; review is unresolved and counted separately", "harmful_reduction": "Predicted reduce on known retain/temporary", "workflow_preservation": "Individual initially executable workflows still executable after permission-wide remove recommendations only", "sensitive_excess_grants": "Effective grants outside documented needs on high/critical resources; not exploit paths", "brier": "Unavailable: heuristic scores are not calibrated probabilities", "latency": "Combined prediction-loop time across all eight systems per evaluated test identity; excludes generation, fitting, upstream simulations and metric aggregation"}, "split_counts": {split: sum(row["split"] == split for row in world["identities"]) for split in ("train", "validation", "test")}}


def benchmark(seeds: list[int], as_of: str) -> dict:
    """Repeat varied synthetic templates without claiming independent generalization."""
    from statistics import mean
    from statistics import pstdev

    from entitleguard.generate import generate_enterprise
    from entitleguard.pipeline import analyze_world

    runs = []
    for seed in seeds:
        started = time.perf_counter()
        world = generate_enterprise(seed, as_of)
        generation_ms = (time.perf_counter() - started) * 1000
        analysis = analyze_world(world)
        metrics = evaluate(world, analysis)
        runs.append({"seed": seed, "dataset_id": metrics["_provenance"]["dataset_id"], "labeled_cases": metrics["labeled_cases"], "full": metrics["systems"]["full"], "scenario_counts": {name: row["n"] for name, row in metrics["scenarios"].items()}, "generation_ms": round(generation_ms, 3)})
    summary = {}
    for key in ("precision", "recall", "f1", "false_removal_rate"):
        values = [run["full"][key] for run in runs if run["full"][key] is not None]
        summary[key] = {"mean": round(mean(values), 4), "stddev": round(pstdev(values), 4), "min": min(values), "max": max(values)} if values else None
    return {"mode": "offline_heuristic", "as_of": as_of, "seeds": seeds, "runs": runs, "summary": summary, "limitations": LIMITATIONS, "note": "Seeds vary recency, redundant sources and log missingness within shared templates. This is robustness, not independent scenario generalization."}
