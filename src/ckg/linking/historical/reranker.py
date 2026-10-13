"""Fuses normalized per-plane features, never raw vector/full-text distances."""

from __future__ import annotations

from pathlib import Path
import yaml

_FALLBACK_WEIGHTS = {
    "same_weakness": 0.35,
    "adjacent_weakness": 0.15,
    "same_technique": 0.20,
    "same_context": 0.15,
    "graph_similarity": 0.15,
    "same_capec_neighborhood": 0.10,
    "same_patch_pattern": 0.15,
    "shared_patch_pattern": 0.10,
}


def load_reranker_weights(path: Path | str | None = None) -> dict[str, float]:
    if path is None:
        default_path = Path(__file__).resolve().parents[3] / "config" / "scoring.yaml"
        if default_path.exists():
            path = default_path
    if path and Path(path).exists():
        try:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
            weights = data.get("reranker_weights")
            if isinstance(weights, dict) and weights:
                return {str(k): float(v) for k, v in weights.items()}
        except Exception:
            pass
    return dict(_FALLBACK_WEIGHTS)


WEIGHTS = load_reranker_weights()


def fuse_sources(sources: frozenset[str], *, weights: dict[str, float] | None = None) -> float:
    effective_weights = WEIGHTS if weights is None else weights
    available = [effective_weights[source] for source in sources if source in effective_weights]
    return sum(available) / sum(effective_weights.values()) if available else 0.0
