# Historical Evaluation Implementation Plan

> **For agentic workers:** This plan is executed inline in the current
> checkout. The worktree already contains user changes and must not be reset
> or cleaned.

**Goal:** Add a real offline historical-replay evaluation feature that uses
hash-addressed CVE snapshots, runs deterministic baseline/ablation variants,
and emits auditable JSON/CSV paper artifacts.

**Architecture:** The evaluator will scan only the explicitly listed JSON CVE
objects in the existing `SnapshotStore`, parse them through the production CVE
parsers, and build a small immutable record view per temporal cutoff. It will
evaluate technology retrieval and CVE→CWE ranking using future-observed
references, while refusing to claim scenario recall or human gold labels. A
separate result serializer will write stable JSONL/CSV artifacts and a CLI will
orchestrate the run without network access.

**Tech Stack:** Python 3.12, dataclasses, PyYAML, existing CVE parsers,
`SnapshotStore`, existing ranking metrics, pytest, standard-library CSV/JSON.

## Global Constraints

- Use only local snapshot objects during evaluation; no implicit network fetch.
- Preserve provenance and fail closed for missing/mismatched snapshot digests.
- Do not call future records training data for a cutoff before their known time.
- Future-observed labels must not be described as adjudicated human gold.
- Do not claim sentence-transformer or graph-embedding results until adapters exist.
- Do not modify credential/default-password/API-auth areas.
- Do not reset, clean, delete or commit pre-existing worktree changes.

### Task 1: Define the pinned historical manifest

**Files:**
- Modify: `datasets/evaluation/manifest.yaml`
- Modify: `docs/architecture/09-evaluation.md`
- Test: `tests/evaluation/test_historical_evaluation.py`

**Interfaces:**
- `load_experiment_config(path)` continues to validate the existing common
  metadata.
- New manifest fields expose `cve_snapshot.objects`, `cutoffs`, `baselines`
  and explicit excluded status for WSTG/PATT when not part of this replay.

- [x] Replace free-form WSTG/PATT placeholders with explicit
  `status: excluded_from_cve_replay` metadata and reason.
- [x] Add the exact CVE object digests currently present in the snapshot store,
  the inventory digest, parser version and historical cutoffs.
- [x] Add baseline identifiers and result schema version.
- [x] Add tests that reject an unpinned object, a missing digest and a future
  record whose published/known time is before the cutoff view.
- [x] Run `.venv/bin/python -m pytest tests/evaluation/test_historical_evaluation.py -q`.

### Task 2: Implement historical record loading and temporal replay

**Files:**
- Create: `src/ckg/evaluation/historical.py`
- Modify: `src/ckg/evaluation/__init__.py`
- Test: `tests/evaluation/test_historical_evaluation.py`

**Interfaces:**
- `load_snapshot_records(snapshot_root: str | Path, object_digests: tuple[str, ...]) -> tuple[HistoricalRecord, ...]`
- `build_historical_view(records: tuple[HistoricalRecord, ...], cutoff: datetime) -> HistoricalView`
- `future_observed_labels(records: tuple[HistoricalRecord, ...], cutoff: datetime) -> dict[str, frozenset[str]]`
- `run_historical_experiment(manifest_path: str | Path, snapshot_root: str | Path) -> EvaluationRun`

- [x] Define frozen record dataclasses containing record ID, source digest,
  published/known time, state, product/vendor names and reported CWE IDs.
- [x] Parse CVE Services and NVD objects through the existing production
  parsers, preserving source digest and object path.
- [x] Fail closed on missing/digest-mismatched objects, unsupported payloads or
  an empty pinned inventory.
- [x] Exclude undated records from temporal train/test metrics and report them
  as diagnostics.
- [x] Ensure the cutoff view contains only records known at or before cutoff;
  future records remain available only to reference-label construction.
- [x] Add regression coverage for future leakage and rejected/withdrawn states.
- [x] Run the focused historical test module.

### Task 3: Implement deterministic baseline variants and metrics

**Files:**
- Modify: `src/ckg/evaluation/historical.py`
- Modify: `src/ckg/evaluation/metrics.py`
- Test: `tests/evaluation/test_historical_evaluation.py`

**Interfaces:**
- `run_baseline(name: str, view: HistoricalView, query: str, *, limit: int) -> tuple[str, ...]`
- `evaluate_cutoff(view: HistoricalView, held_out: tuple[HistoricalRecord, ...], baselines: tuple[str, ...], k: int) -> tuple[MetricRow, ...]`

- [x] Implement `keyword-v1` using normalized product/vendor identity.
- [x] Implement `bm25-v1` as a dependency-free lexical ranking baseline.
- [x] Implement `lexical-hash-v1` using the existing deterministic lexical
  embedding without claiming a production semantic encoder.
- [x] Implement graph/evidence/temporal/provenance variants as explicit,
  inspectable gates over the same candidate set.
- [x] Keep candidate ordering deterministic by relevance, publication time and
  stable ID.
- [x] Use existing Precision@K, Recall@K, MRR, nDCG@K and multi-label F1.
- [x] Return `not_evaluable`/`None` when a reference set is incomplete rather
  than fabricating zero scores.
- [x] Test that every baseline receives the same cutoff and held-out records.

### Task 4: Add stable result serialization and CLI

**Files:**
- Create: `src/ckg/evaluation/results.py`
- Create: `scripts/run_historical_evaluation.py`
- Modify: `src/ckg/evaluation/__init__.py`
- Test: `tests/evaluation/test_historical_evaluation.py`

**Interfaces:**
- `write_evaluation_run(run: EvaluationRun, output_dir: str | Path) -> None`
- `main(argv: Sequence[str] | None = None) -> int`
- CLI: `python -m scripts.run_historical_evaluation --manifest datasets/evaluation/manifest.yaml --snapshot-root registry/upstream_snapshots --output-dir datasets/evaluation/results`

- [x] Serialize `summary.json`, `results.jsonl`, `results.csv`,
  `predictions.jsonl` and a generated run README.
- [x] Include manifest digest, source object digests, parser version, current
  commit if available, cutoff, baseline, task, counts and diagnostics.
- [x] Keep predictions bounded and store only evidence IDs/digests, never
  secret values or raw credentials.
- [x] Make repeated runs byte-stable except for an explicitly recorded run
  timestamp field; use a deterministic mode for committed artifacts.
- [x] Add CLI tests for offline execution and malformed manifest failure.

### Task 5: Generate real local evaluation artifacts

**Files:**
- Create: `datasets/evaluation/results/summary.json`
- Create: `datasets/evaluation/results/results.jsonl`
- Create: `datasets/evaluation/results/results.csv`
- Create: `datasets/evaluation/results/predictions.jsonl`
- Create: `datasets/evaluation/results/README.md`

- [x] Run the CLI against the pinned CVE objects already in the repository.
- [x] Preserve diagnostics for undated records and insufficient historical
  coverage; do not hide small-sample limitations.
- [x] Verify JSON/JSONL/CSV schemas and ensure the result reports its actual
  sample size and evaluability status.

### Task 6: Fix documentation, UI wording and build reproducibility

**Files:**
- Modify: `README.md`
- Modify: `src/ckg/ui/v2/index.html`
- Modify: `src/ckg/ui/v2/app.js`
- Modify: `pyproject.toml`
- Test: `tests/integration/test_v2_api.py`
- Test: `tests/integration/test_v2_ui_browser.py`

- [x] Close the README code fence before diagnostic prose.
- [x] Render backend status from `/healthz` instead of hardcoding `Neo4j Live`.
- [x] Rename the scenario heading to semantic/non-executable wording.
- [x] Pin the build backend dependency to the installed supported version and
  document an offline-capable build command without touching credentials.
- [x] Add HTTP/static assertions for the corrected UI copy and backend status.

### Task 7: Verification checkpoint

- [x] Run focused evaluator tests.
- [ ] Run `.venv/bin/python -m pytest -q -rs` with the configured Neo4j test service.
- [x] Run the historical CLI and inspect generated metrics/diagnostics.
- [ ] Run canonical and migration verifiers, including strict mode.
- [ ] Run AST/YAML validation and `git diff --check`.
- [x] Attempt the wheel build with the documented offline/cache settings and
  report environment blockers separately from code failures.
- [ ] Review `git diff` and preserve all unrelated pre-existing changes.
