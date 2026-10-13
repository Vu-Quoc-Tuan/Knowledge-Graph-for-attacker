"""Load and validate reproducible evaluation metadata before an experiment."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ExperimentConfig:
    schema_version: int
    cutoff: datetime
    source_versions: dict[str, str]
    random_seed: int
    embedding_version: str
    scoring_config_version: str
    model_version: str
    prompt_version: str
    annotation_policy: str


_REQUIRED = frozenset({
    "schema_version", "cutoff", "source_versions", "random_seed",
    "embedding_version", "scoring_config_version", "model_version",
    "prompt_version", "annotation_policy",
})


def experiment_config_from_mapping(value: dict[str, Any]) -> ExperimentConfig:
    missing = sorted(_REQUIRED - set(value))
    if missing:
        raise ValueError(f"evaluation manifest missing required metadata: {', '.join(missing)}")
    if not isinstance(value["source_versions"], dict) or not value["source_versions"]:
        raise ValueError("source_versions must be a non-empty mapping")
    try:
        cutoff = datetime.fromisoformat(str(value["cutoff"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("cutoff must be ISO-8601") from exc
    if cutoff.tzinfo is None:
        raise ValueError("cutoff must include timezone")
    if not isinstance(value["random_seed"], int):
        raise ValueError("random_seed must be an integer")
    for key in ("embedding_version", "scoring_config_version", "model_version", "prompt_version", "annotation_policy"):
        if not isinstance(value[key], str) or not value[key].strip():
            raise ValueError(f"{key} must be a non-empty string")
    return ExperimentConfig(
        schema_version=int(value["schema_version"]),
        cutoff=cutoff,
        source_versions={str(key): str(item) for key, item in value["source_versions"].items()},
        random_seed=value["random_seed"],
        embedding_version=value["embedding_version"],
        scoring_config_version=value["scoring_config_version"],
        model_version=value["model_version"],
        prompt_version=value["prompt_version"],
        annotation_policy=value["annotation_policy"],
    )


def load_experiment_config(path: str | Path) -> ExperimentConfig:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("evaluation manifest must be a YAML mapping")
    return experiment_config_from_mapping(payload)
