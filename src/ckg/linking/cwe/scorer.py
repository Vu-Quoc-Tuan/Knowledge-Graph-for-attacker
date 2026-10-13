"""Missing-modality-aware scoring; absent evidence never becomes a zero score."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import warnings

import yaml

_FALLBACK_WEIGHTS = {
    "explicit_identifier": 1.0,
    "structured_cwe": 1.0,
    "rule_text": 0.45,
    "lexical": 0.35,
    "patch_diff": 0.90,
}


def load_modality_weights(path: Path | str | None = None) -> dict[str, float]:
    if path is None:
        default_path = Path(__file__).resolve().parents[2] / "config" / "scoring.yaml"
        if default_path.exists():
            path = default_path
    if path and Path(path).exists():
        try:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
            modalities = data.get("modalities")
            if isinstance(modalities, dict) and modalities:
                return {str(k): float(v) for k, v in modalities.items()}
        except Exception as exc:
            warnings.warn(
                f"failed to load modality weights from {path}: {exc}; using defaults",
                RuntimeWarning,
                stacklevel=2,
            )
    return dict(_FALLBACK_WEIGHTS)


DEFAULT_WEIGHTS = load_modality_weights()


@dataclass(frozen=True)
class LinkScore:
    relevance: float | None
    evidence_coverage: float
    present_modalities: tuple[str, ...]


def score_modalities(modality_scores: dict[str, float], *, weights: dict[str, float] | None = None) -> LinkScore:
    effective_weights = DEFAULT_WEIGHTS if weights is None else weights
    present = {key: value for key, value in modality_scores.items() if key in effective_weights}
    if not present:
        return LinkScore(relevance=None, evidence_coverage=0.0, present_modalities=())
    denominator = sum(effective_weights[key] for key in present)
    relevance = sum(effective_weights[key] * value for key, value in present.items()) / denominator
    coverage = denominator / sum(effective_weights.values())
    return LinkScore(relevance=relevance, evidence_coverage=coverage, present_modalities=tuple(sorted(present)))
