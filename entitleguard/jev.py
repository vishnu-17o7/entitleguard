"""Jev contextual judgments. The benchmark uses the heuristic. The console can call Jev 1.13."""
from __future__ import annotations

import hashlib
import json
import math
import os
import time
from datetime import datetime
from datetime import timezone
from typing import Any

import httpx

from config import JEV_OPENROUTER_MODEL
from config import JEV_SCHEMA_VERSION
from config import JEV_TYPESAFE_MODEL
from config import OPENROUTER_DECISIONS_URL
from config import TYPESAFE_SYSTEMONE_URL
from config import jev_provider
from entitleguard.catalog import PURPOSE_WORDS

QUESTIONS: dict[str, dict[str, Any]] = {
    "role_consistency": {
        "type": "noul",
        "instructions": (
            "This permission is consistent with the documented job responsibility. "
            "Judge only the stated role, team, and duty. Do not treat unused access "
            "as proof that the permission is unnecessary."
        ),
        "criteria": {
            "true": "The permission fits the stated responsibility.",
            "false": "The permission does not fit the stated responsibility.",
        },
    },
    "rare_usage_plausible": {
        "type": "noul",
        "instructions": (
            "Rare or absent recent usage is plausibly explained by the stated duties, "
            "a quarterly or monthly cadence, or an approved exception."
        ),
        "criteria": {
            "true": "Infrequent use fits the duty or cadence.",
            "false": "Infrequent use is not explained by the duty or cadence.",
        },
    },
    "review_priority": {
        "type": "choice",
        "instructions": "How should this permission case be triaged?",
        "criteria": {
            "standard": "No unusual contextual concern.",
            "investigate": "Possible privilege mismatch. A person should look.",
            "urgent": "Sensitive mismatch that needs prompt review.",
        },
    },
}


def build_state(
    *,
    role_title: str,
    team: str,
    responsibility: str,
    action: str,
    resource_name: str,
    sensitivity: str,
    last_used_days: int | None,
    approved_exception: bool,
    in_documented_duties: bool,
    workflow_cadence: str | None,
) -> dict[str, Any]:
    """Context for one permission. This is not an authorization decision."""
    return {
        "identity_role": role_title,
        "team": team,
        "current_responsibility": responsibility,
        "permission": action,
        "resource": resource_name,
        "resource_sensitivity": sensitivity,
        "last_used_days": last_used_days,
        "approved_exception": approved_exception,
        "in_documented_duties": in_documented_duties,
        "workflow_cadence": workflow_cadence,
    }


def _words_match(action: str, responsibility: str) -> bool:
    text = responsibility.lower()
    return any(word in text for word in PURPOSE_WORDS.get(action, ()))


def heuristic_judge(state: dict[str, Any]) -> dict[str, Any]:
    """Reproducible stand-in with the same question schema as Jev."""
    started = time.perf_counter()
    if state["in_documented_duties"]:
        consistency = 0.92
    elif state["approved_exception"]:
        consistency = 0.74
    elif state.get("workflow_cadence") == "quarterly" and state["permission"] == "db:Restore":
        consistency = 0.88
    elif _words_match(str(state["permission"]), str(state["current_responsibility"])):
        consistency = 0.76
    else:
        consistency = 0.16
    last_used = state["last_used_days"]
    explained = consistency >= 0.55 or state.get("workflow_cadence") in {"quarterly", "monthly"}
    if last_used is None:
        rare = 0.35
    elif last_used > 90 and explained:
        rare = 0.81
    elif last_used > 90:
        rare = 0.14
    else:
        rare = 0.72
    if consistency < 0.3 and state["resource_sensitivity"] == "critical":
        choice = "urgent"
        probs = {"standard": 0.05, "investigate": 0.25, "urgent": 0.70}
    elif consistency < 0.55:
        choice = "investigate"
        probs = {"standard": 0.15, "investigate": 0.70, "urgent": 0.15}
    else:
        choice = "standard"
        probs = {"standard": 0.78, "investigate": 0.18, "urgent": 0.04}
    latency = (time.perf_counter() - started) * 1000
    return _envelope(
        consistency=consistency,
        rare=rare,
        choice=choice,
        probs=probs,
        model="heuristic-jev-compatible",
        provider="heuristic",
        latency_ms=latency,
    )


def _envelope(
    *,
    consistency: float,
    rare: float,
    choice: str,
    probs: dict[str, float],
    model: str,
    provider: str,
    latency_ms: float,
    usage: dict | None = None,
) -> dict[str, Any]:
    return {
        "provider": provider,
        "model": model,
        "schema_version": JEV_SCHEMA_VERSION,
        "score_semantics": "heuristic_score" if provider.startswith("heuristic") else "provider_probability",
        "latency_ms": round(latency_ms, 2),
        "usage": usage or {},
        "answers": {
            "role_consistency": {"type": "noul", "noul": round(consistency, 4)},
            "rare_usage_plausible": {"type": "noul", "noul": round(rare, 4)},
            "review_priority": {
                "type": "choice",
                "choice": choice,
                "probabilities": probs,
                "confidence": round(max(probs.values()), 4),
            },
        },
    }


def consistency_of(judgment: dict[str, Any]) -> float:
    """Return the role-consistency probability."""
    return float(judgment["answers"]["role_consistency"]["noul"])


class JevClient:
    """Pinned Jev 1.13 client. Falls back to the heuristic if the call fails."""

    def __init__(self, provider: str | None = None, timeout: float = 25.0) -> None:
        self.provider = provider or jev_provider()
        self.timeout = timeout

    def judge(self, state: dict[str, Any]) -> dict[str, Any]:
        """Ask the three entitlement questions."""
        if self.provider == "heuristic":
            judgment = heuristic_judge(state)
            judgment["judged_at"] = datetime.now(timezone.utc).isoformat()
            judgment["input_hash"] = hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
            return judgment
        try:
            judgment = self._remote(state)
            judgment["judged_at"] = datetime.now(timezone.utc).isoformat()
            judgment["input_hash"] = hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
            return judgment
        except Exception as exc:
            judgment = heuristic_judge(state)
            judgment["provider"] = "heuristic-fallback"
            judgment["error"] = type(exc).__name__
            judgment["fallback_reason"] = str(exc)[:200]
            judgment["requested_provider"] = self.provider
            judgment["judged_at"] = datetime.now(timezone.utc).isoformat()
            judgment["input_hash"] = hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
            return judgment

    def _remote(self, state: dict[str, Any]) -> dict[str, Any]:
        started = time.perf_counter()
        if self.provider == "typesafe":
            url = TYPESAFE_SYSTEMONE_URL
            headers = {
                "Authorization": f"Bearer {os.getenv('TYPESAFE_API_KEY', '')}",
                "Content-Type": "application/json",
            }
            model = JEV_TYPESAFE_MODEL
        else:
            url = OPENROUTER_DECISIONS_URL
            headers = {
                "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY', '')}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://localhost/entitleguard",
                "X-OpenRouter-Title": "EntitleGuard",
            }
            model = JEV_OPENROUTER_MODEL
        body = {"model": model, "state": state, "questions": QUESTIONS, "schema_version": JEV_SCHEMA_VERSION}
        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, headers=headers, json=body)
            response.raise_for_status()
            payload = response.json()
        latency = (time.perf_counter() - started) * 1000
        if payload.get("model") != model:
            raise ValueError("Unexpected model identity")
        if payload.get("schema_version") != JEV_SCHEMA_VERSION:
            raise ValueError("Unexpected question schema")
        answers = payload.get("answers")
        if not isinstance(answers, dict) or set(answers) != set(QUESTIONS):
            raise ValueError("Missing or unexpected answers")
        role = answers["role_consistency"]
        rare = answers["rare_usage_plausible"]
        review = answers["review_priority"]
        def probability(value: Any) -> float:
            if isinstance(value, bool) or not isinstance(value, (float, int)):
                raise ValueError("Probability must be numeric")
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError("Probability outside [0,1]")
            return float(value)
        consistency = probability(role["noul"])
        rare_value = probability(rare["noul"])
        if role.get("type") != "noul" or rare.get("type") != "noul" or review.get("type") != "choice":
            raise ValueError("Unexpected answer type")
        probs = {key: probability(value) for key, value in review["probabilities"].items()}
        choice = review["choice"]
        if set(probs) != set(QUESTIONS["review_priority"]["criteria"]) or choice not in probs:
            raise ValueError("Invalid review choices")
        if abs(sum(probs.values()) - 1) > 0.001:
            raise ValueError("Review probabilities must sum to one")
        return _envelope(
            consistency=consistency,
            rare=rare_value,
            choice=choice,
            probs=probs,
            model=str(payload.get("model") or model),
            provider=self.provider,
            latency_ms=latency,
            usage=payload.get("usage") or {},
        )
