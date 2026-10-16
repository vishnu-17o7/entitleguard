from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("ENTITLEGUARD_DATA_DIR", str(ROOT / "data"))).resolve()
RESULTS_DIR = Path(os.getenv("ENTITLEGUARD_RESULTS_DIR", str(ROOT / "results"))).resolve()
DB_PATH = RESULTS_DIR / "approvals.sqlite"

# Only this project may supply secrets; live calls require explicit opt-in.
load_dotenv(ROOT / ".env")

SEED = 42
N_EMPLOYEES = 500  # Human population: 490 employees and 10 contractors
N_CONTRACTORS = 10
N_SERVICES = 75
HISTORY_START = "2026-04-17"
AS_OF = "2026-10-14"
TRANSFER_DATE = "2026-07-01"

JEV_PINNED_MODEL = "typesafe/jev-1.13"
JEV_OPENROUTER_MODEL = "typesafe/jev-1.13"
JEV_TYPESAFE_MODEL = "jev-1.13.0"
OPENROUTER_DECISIONS_URL = "https://openrouter.ai/api/alpha/decisions"
TYPESAFE_SYSTEMONE_URL = "https://api.typesafe.ai/v1/systemone"
JEV_SCHEMA_VERSION = "entitle-q-v1"

HOST = "127.0.0.1"
PORT = 8520


def jev_provider() -> str:
    """Return typesafe, openrouter, or heuristic."""
    forced = os.getenv("JEV_PROVIDER", "").strip().lower()
    if forced in {"typesafe", "openrouter", "heuristic"}:
        return forced
    return "heuristic"
