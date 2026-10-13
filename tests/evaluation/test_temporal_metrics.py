from datetime import datetime, timezone


def test_temporal_split_excludes_missing_times_and_metrics_are_multi_label() -> None:
    from ckg.evaluation.metrics import ranking_metrics
    from ckg.evaluation.temporal_split import temporal_split

    split = temporal_split((
        ("old", datetime(2025, 1, 1, tzinfo=timezone.utc)),
        ("new", datetime(2027, 1, 1, tzinfo=timezone.utc)),
        ("undated", None),
    ), cutoff=datetime(2026, 1, 1, tzinfo=timezone.utc))
    metrics = ranking_metrics({"new": ("CWE-79", "CWE-89")}, {"new": frozenset({"CWE-79", "CWE-611"})}, k=2)

    assert split.train_ids == ("old",)
    assert split.test_ids == ("new",)
    assert split.excluded_ids == ("undated",)
    assert metrics["precision_at_k"] == 0.5
    assert metrics["recall_at_k"] == 0.5
    assert metrics["mrr"] == 1.0


def test_ablation_uses_shared_evaluator() -> None:
    from ckg.evaluation.ablation import run_ablations

    result = run_ablations(("cwe", "capec", "wstg"), lambda enabled: float(len(enabled)))

    assert result["full"] == 3.0
    assert result["incremental:2"] == 2.0
    assert result["leave_one_out:wstg"] == 2.0


def test_ranking_metrics_do_not_count_duplicate_prediction_twice() -> None:
    from ckg.evaluation.metrics import ranking_metrics

    metrics = ranking_metrics(
        {"new": ("CWE-79", "CWE-79")},
        {"new": frozenset({"CWE-79"})},
        k=2,
    )

    assert metrics["recall_at_k"] == 1.0
    assert metrics["ndcg_at_k"] == 1.0


def test_multilabel_scenario_metrics_and_frozen_evolving_protocols() -> None:
    from ckg.evaluation.metrics import multi_label_f1, scenario_metrics
    from ckg.evaluation.protocols import DecisionRecord, FeedbackRecord, evolving_protocol, frozen_protocol

    cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
    decisions = (DecisionRecord("old", datetime(2025, 12, 1, tzinfo=timezone.utc)), DecisionRecord("new", datetime(2026, 2, 1, tzinfo=timezone.utc)))
    feedback = (FeedbackRecord("too-early", datetime(2025, 12, 2, tzinfo=timezone.utc)), FeedbackRecord("available", datetime(2026, 1, 15, tzinfo=timezone.utc)), FeedbackRecord("future", datetime(2026, 3, 1, tzinfo=timezone.utc)))

    f1 = multi_label_f1({"new": frozenset({"CWE-79", "CWE-89"})}, {"new": frozenset({"CWE-79", "CWE-611"})})
    scenario = scenario_metrics({"new": ("SCN-1", "SCN-2")}, {"new": frozenset({"SCN-1"})}, applicability_judgments={("new", "SCN-1"): True}, grounding_judgments={("new", "SCN-1"): True, ("new", "SCN-2"): False}, known_training_scenarios=frozenset({"SCN-1"}), reference_set_complete=False)

    assert f1["micro_f1"] == f1["example_f1"] == 0.5
    assert frozen_protocol(decisions, cutoff=cutoff) == ("new",)
    assert evolving_protocol(decisions, feedback, cutoff=cutoff)[0].available_feedback_ids == ("available",)
    assert scenario["scenario_precision"] == scenario["grounding_rate"] == scenario["novelty_rate"] == 0.5
    assert scenario["applicability_precision"] == 1.0
    assert scenario["scenario_recall"] is None


def test_scenario_metrics_duplicate_prediction_does_not_inflate_recall() -> None:
    from ckg.evaluation.metrics import scenario_metrics

    metrics = scenario_metrics(
        {"cve-1": ("SCN-1", "SCN-1")},
        {"cve-1": frozenset({"SCN-1"})},
        applicability_judgments={("cve-1", "SCN-1"): True},
        grounding_judgments={("cve-1", "SCN-1"): True},
        known_training_scenarios=frozenset(),
        reference_set_complete=True,
    )

    # Recall and precision must be 1.0, never inflated to 2.0!
    assert metrics["scenario_recall"] == 1.0
    assert metrics["scenario_precision"] == 1.0



def test_experiment_manifest_pins_required_reproducibility_metadata() -> None:
    from ckg.evaluation.runner import experiment_config_from_mapping, load_experiment_config

    config = load_experiment_config("datasets/evaluation/manifest.yaml")
    assert config.cutoff.year == 2026
    assert config.model_version == "deterministic-replay-v1"
    try:
        experiment_config_from_mapping({"schema_version": 1})
    except ValueError as exc:
        assert "missing required metadata" in str(exc)
    else:
        raise AssertionError("incomplete experiment metadata must fail")
