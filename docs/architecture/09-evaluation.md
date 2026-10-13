# Evaluation

Use `datasets/evaluation/manifest.yaml` as the immutable experiment input. It
pins cutoff, source release/commit IDs, scoring/embedding/model/prompt
versions and seed. `load_experiment_config()` refuses a missing field or a
timezone-less cutoff.

Frozen and evolving protocols are intentionally different. Frozen evaluates
only decisions after cutoff and admits no later feedback. Evolving evaluates
the same held-out stream but exposes only feedback whose `available_at` is at
or before each decision; a later observation cannot leak backward.

Linking is multi-label: report Precision@K, Recall@K, MRR, nDCG@K and
micro/macro F1 after choosing thresholds on a validation split. Retrieval has
the same ranked metrics only with relevance judgments. Scenario precision,
applicability, grounding and novelty use adjudicated labels. Recall is emitted
only when the reference set defines the applicable scenario population.
Ablation uses one shared corpus, split and subgraph budget for full,
incremental-stack and leave-one-source-out runs.
