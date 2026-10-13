# Historical Evaluation and Reproducible Baselines

**Status:** approved design, pending implementation

## Goal

Turn the evaluation scaffold into a reproducible historical replay pipeline
for the provenance-first vulnerability CKG. The pipeline must learn or rank
using information available at a historical cutoff and evaluate against
records observed after that cutoff, without leaking future source state into
the historical graph.

The primary research contribution is the evidence-gated, temporally isolated
pipeline, not the existence of a static CVE/CWE graph or an unverified claim
of semantic embeddings.

## Scope

The implementation will add:

1. A versioned evaluation manifest with concrete source release/commit and
   snapshot digest metadata.
2. A historical replay evaluator that consumes local, hash-addressed source
   snapshots and produces per-cutoff results.
3. Explicit future-observed reference labels for CVE/technology retrieval and
   CVE/weakness link prediction. These labels are not called human gold.
4. A result schema with JSON and CSV output, run metadata, diagnostics and
   promotion/evaluability status.
5. Deterministic baseline variants:
   `keyword`, `bm25`, `lexical-hash`, `graph-only`, `graph-evidence`,
   `graph-temporal`, `graph-provenance`, and `graph-full`.
6. Regression tests for temporal leakage, label construction, baseline
   determinism, metrics, and result serialization.
7. Documentation and UI wording fixes that make the semantic/non-executable
   boundary and selected backend explicit.

Credential rotation, default-password removal and API authentication remain
out of scope for this change.

## Data contract

The experiment manifest is the single input contract. Every source used by an
experiment must provide:

- source identifier and URL;
- release or immutable commit;
- snapshot digest;
- retrieval timestamp;
- parser/normalizer version.

WSTG and PayloadsAllTheThings must not use a free-form
`pinned-per-experiment` placeholder. An experiment fails closed when a source
cannot be resolved to a concrete commit/release and digest.

The evaluator accepts only local snapshot objects. Network fetching is a
separate explicit bootstrap operation and is never performed by an evaluation
run.

## Historical protocol

For each cutoff `t`:

1. Load only canonical records and source evidence known at or before `t`.
2. Build the graph/retrieval view from that historical state.
3. Generate predictions for held-out records after `t`.
4. Construct future-observed reference labels only from later source snapshots.
5. Exclude rejected/withdrawn records according to the source state policy.
6. Record excluded, unresolved and unavailable evidence rather than silently
   converting it into negatives.

The evaluator must emit `not_evaluable` when a reference population is not
complete. Scenario recall remains unavailable without a complete adjudicated
reference set.

## Baseline contract

All variants run over the same source snapshots, cutoffs, candidate limits,
random seed and output schema.

- `keyword-v1`: normalized product/vendor keyword matching.
- `bm25-v1`: dependency-free document ranking over the same visible CVE text.
- `lexical-hash-v1`: current deterministic hashing embedding baseline.
- `graph-only-v1`: graph structure without evidence gating.
- `graph-evidence-v1`: graph plus source/evidence presence.
- `graph-temporal-v1`: graph plus as-of temporal filtering.
- `graph-provenance-v1`: graph plus evidence/status promotion gates.
- `graph-full-v1`: all canonical v2 gates and ranking inputs.

No sentence-transformer or graph-embedding result is reported until that
adapter is implemented, versioned and included in the same replay protocol.

## Result contract

Each run writes:

- `summary.json`: experiment identity, commit, manifest digest, source
  digests, run status, diagnostics and aggregate metrics;
- `results.jsonl`: one row per cutoff, task and baseline;
- `results.csv`: flat table for paper tables;
- `predictions.jsonl`: bounded predictions and evidence identifiers needed for
  audit, without secret values;
- `README.md`: exact command and interpretation of future-observed labels.

Metrics include Precision@K, Recall@K, MRR, nDCG@K and multi-label F1 where a
reference set exists. Scenario precision, applicability, grounding and
novelty require adjudicated labels and are not fabricated by this pipeline.

## Code boundaries

- `src/ckg/evaluation/historical.py` owns replay, reference construction and
  baseline orchestration.
- `src/ckg/evaluation/results.py` owns stable result records and serialization.
- `scripts/run_historical_evaluation.py` is the explicit CLI entry point.
- `datasets/evaluation/` contains manifests, reference metadata and generated
  experiment artifacts; raw upstream objects remain in the existing snapshot
  store.

The evaluator will use existing graph ports and parsers rather than creating a
second graph schema or reusing the legacy UI graph.

## Acceptance criteria

The change is complete when:

1. A local historical run completes without network access.
2. The manifest contains concrete source identifiers and digest metadata.
3. A future record cannot influence a prediction made before its availability
   time; a regression test proves this.
4. All baseline variants produce deterministic output under the fixed seed.
5. JSON and CSV result artifacts are generated from the same run and pass
   schema validation.
6. The evaluator reports diagnostics and refuses promotion/evaluation when
   source snapshots or reference labels are incomplete.
7. Full pytest, the historical evaluator, canonical/migration verifiers and
   the package build are run and their outcomes are documented.
8. The UI identifies the actual backend and describes scenarios as semantic,
   non-executable scenarios.
