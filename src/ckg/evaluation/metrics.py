from __future__ import annotations

import math
from collections.abc import Mapping


def ranking_metrics(predictions: dict[str, tuple[str, ...]], truth: dict[str, frozenset[str]], *, k: int) -> dict[str, float]:
    """Multi-label Precision@K, Recall@K, MRR and nDCG@K over judged records."""
    if k < 1:
        raise ValueError("k must be positive")
    values = []
    for identifier, expected in truth.items():
        ranked = predictions.get(identifier, ())[:k]
        # A repeated candidate cannot count as a second retrieved label. Keep
        # its rank cost (Precision@K remains over K positions) but do not let
        # it inflate recall or DCG above their valid range.
        seen: set[str] = set()
        hits = []
        for index, item in enumerate(ranked, start=1):
            if item in seen:
                continue
            seen.add(item)
            if item in expected:
                hits.append(index)
        precision = len(hits) / k
        recall = len(hits) / len(expected) if expected else 0.0
        reciprocal = 1 / hits[0] if hits else 0.0
        dcg = sum(1 / math.log2(index + 1) for index in hits)
        ideal = sum(1 / math.log2(index + 1) for index in range(1, min(k, len(expected)) + 1))
        values.append((precision, recall, reciprocal, dcg / ideal if ideal else 0.0))
    if not values:
        return {"precision_at_k": 0.0, "recall_at_k": 0.0, "mrr": 0.0, "ndcg_at_k": 0.0, "n": 0.0}
    return {"precision_at_k": sum(value[0] for value in values) / len(values), "recall_at_k": sum(value[1] for value in values) / len(values), "mrr": sum(value[2] for value in values) / len(values), "ndcg_at_k": sum(value[3] for value in values) / len(values), "n": float(len(values))}


def multi_label_f1(predictions: Mapping[str, frozenset[str]], truth: Mapping[str, frozenset[str]]) -> dict[str, float]:
    """Report micro F1, label-averaged macro F1, and per-record example F1."""
    ids = tuple(sorted(set(predictions) | set(truth)))
    all_labels = {label for s in predictions.values() for label in s} | {label for s in truth.values() for label in s}
    per_record: list[float] = []
    true_positive = false_positive = false_negative = 0
    for identifier in ids:
        predicted = predictions.get(identifier, frozenset())
        expected = truth.get(identifier, frozenset())
        tp = len(predicted & expected)
        fp = len(predicted - expected)
        fn = len(expected - predicted)
        true_positive += tp
        false_positive += fp
        false_negative += fn
        denominator = 2 * tp + fp + fn
        per_record.append((2 * tp / denominator) if denominator else 1.0)
    label_f1s = []
    for label in all_labels:
        l_tp = sum(label in predictions.get(i, frozenset()) and label in truth.get(i, frozenset()) for i in ids)
        l_fp = sum(label in predictions.get(i, frozenset()) and label not in truth.get(i, frozenset()) for i in ids)
        l_fn = sum(label not in predictions.get(i, frozenset()) and label in truth.get(i, frozenset()) for i in ids)
        l_denom = 2 * l_tp + l_fp + l_fn
        label_f1s.append((2 * l_tp / l_denom) if l_denom else 0.0)
    denominator = 2 * true_positive + false_positive + false_negative
    return {
        "micro_f1": (2 * true_positive / denominator) if denominator else 0.0,
        "macro_f1": sum(label_f1s) / len(label_f1s) if label_f1s else 0.0,
        "example_f1": sum(per_record) / len(per_record) if per_record else 0.0,
        "n": float(len(ids)),
    }


def scenario_metrics(
    predictions: Mapping[str, tuple[str, ...]],
    adjudicated_positive: Mapping[str, frozenset[str]],
    *,
    applicability_judgments: Mapping[tuple[str, str], bool],
    grounding_judgments: Mapping[tuple[str, str], bool],
    known_training_scenarios: frozenset[str],
    reference_set_complete: bool,
) -> dict[str, float | None]:
    """Scenario metrics only consume adjudicated labels.

    Applicability and grounding are measured over the subset that reviewers
    actually judged.  Recall is deliberately withheld when the reference set
    cannot define the whole applicable population.
    """
    unique_emitted = list({(case_id, scenario_id) for case_id, scenarios in predictions.items() for scenario_id in scenarios})
    precise = sum(scenario_id in adjudicated_positive.get(case_id, frozenset()) for case_id, scenario_id in unique_emitted)
    applicability = [value for key, value in applicability_judgments.items() if key in set(unique_emitted)]
    grounding = [value for key, value in grounding_judgments.items() if key in set(unique_emitted)]
    observed_positive = sum(len(values) for values in adjudicated_positive.values())
    recall = precise / observed_positive if reference_set_complete and observed_positive else (0.0 if reference_set_complete else None)
    return {
        "scenario_precision": precise / len(unique_emitted) if unique_emitted else 0.0,
        "applicability_precision": sum(applicability) / len(applicability) if applicability else 0.0,
        "grounding_rate": sum(grounding) / len(grounding) if grounding else 0.0,
        "novelty_rate": sum(scenario_id not in known_training_scenarios for _, scenario_id in unique_emitted) / len(unique_emitted) if unique_emitted else 0.0,
        "scenario_recall": recall,
        "n_emitted": float(len(unique_emitted)),
    }
