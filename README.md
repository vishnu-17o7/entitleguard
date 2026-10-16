# EntitleGuard

EntitleGuard reviews effective permissions in a synthetic organisation. It reconstructs each grant from its sources, compares the grant with documented duties, workflows, exceptions, usage, and training-peer prevalence, and records one of five outcomes: retain, remove, reduce, temporary, or review.

An Isolation Forest supplies a separate anomaly signal. It does not authorise a removal. A removal is written only after a counterfactual check, and only to a saved copy of the directory. The original generated snapshot stays in place.

The experiment reported for the lab used the offline heuristic. Hosted judgment is optional.

## Run

```bash
python -m pip install -r requirements.txt
python run.py all --seed 42 --as-of 2026-10-14
python run.py serve
```

The service uses the host and port in `config.py`.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Layout

- `entitleguard/` holds policy resolution, simulation, recommendations, evaluation, and the assessment
- `api.py` is the HTTP interface
- `web/` is the browser console
- `tests/` holds the regression tests

Generated snapshots and the decision ledger are created when the program runs. They are not stored in this repository. Credentials are read from the environment and are not included.
