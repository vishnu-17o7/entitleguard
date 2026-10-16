"""Peer-grouped isolation forest. It proposes candidates. It does not authorize."""
from __future__ import annotations

from collections import defaultdict

import numpy as np
from sklearn.ensemble import IsolationForest

from entitleguard.drift import drift_report
from entitleguard.policy import Directory


def _features(directory: Directory, identity: dict, peer_median: dict[str, float]) -> list[float]:
    granted, _sources = directory.effective(identity)
    privileged = 0
    critical = 0
    recency: list[int] = []
    for permission_id in granted:
        permission = directory.permissions[permission_id]
        if permission["privileged"]:
            privileged += 1
        sensitivity = directory.resources[permission["resource_id"]]["sensitivity"]
        if sensitivity in {"high", "critical"}:
            critical += 1
        usage = directory.usage_for(identity["id"], permission_id)
        recency.append(180 if usage is None else int(usage["last_used_days"]))
    report = drift_report(directory, identity)
    opened = report["timeline"][0]["granted"] if report["timeline"] else len(granted)
    median = peer_median.get(identity["role_id"], float(len(granted)))
    return [
        float(len(granted)),
        privileged / max(1, len(granted)),
        float(critical),
        float(np.mean(recency) if recency else 180.0),
        float(len(granted) - opened),
        float(len(granted) - median),
    ]


def fit_behavior(directory: Directory) -> dict:
    """Fit on the train split and score every identity."""
    train = [row for row in directory.world["identities"] if row["split"] == "train"]
    counts: dict[str, list[int]] = defaultdict(list)
    holders: dict[tuple[str, str], int] = defaultdict(int)
    peers: dict[str, int] = defaultdict(int)
    for identity in train:
        granted, _sources = directory.effective(identity)
        counts[identity["role_id"]].append(len(granted))
        if identity["status"] != "active":
            continue
        peers[identity["role_id"]] += 1
        for permission_id in granted:
            holders[(identity["role_id"], permission_id)] += 1
    peer_median = {role: float(np.median(values)) for role, values in counts.items()}
    prevalence = {
        f"{role}:{permission_id}": holders[(role, permission_id)] / peers[role]
        for role, permission_id in holders
        if peers[role]
    }
    identities = directory.world["identities"]
    matrix = np.array([_features(directory, row, peer_median) for row in identities], dtype=float)
    train_index = [index for index, row in enumerate(identities) if row["split"] == "train"]
    model = IsolationForest(
        n_estimators=100,
        contamination=0.12,
        random_state=int(directory.world["meta"]["seed"]),
    )
    model.fit(matrix[train_index])
    raw = -model.decision_function(matrix)
    train_raw = raw[train_index]
    low = float(train_raw.min())
    high = float(train_raw.max())
    span = max(1e-6, high - low)
    scores = {
        row["id"]: round(float(np.clip((value - low) / span, 0.0, 1.0)), 4)
        for row, value in zip(identities, raw)
    }
    threshold = round(float(np.quantile([scores[row["id"]] for row in train], 0.88)), 4)
    return {
        "scores": scores,
        "threshold": threshold,
        "prevalence": prevalence,
        "peer_median": {role: round(value, 2) for role, value in peer_median.items()},
    }


def peer_prevalence(model: dict, role_id: str, permission_id: str) -> float:
    """Fraction of train peers in this role who hold the permission."""
    return float(model["prevalence"].get(f"{role_id}:{permission_id}", 0.0))
