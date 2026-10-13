from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from db.sink import GraphSink
from schema.models import DetectionSignal, FAMILY_KEY_PATTERN
from utils.identifiers import WEAKNESS_ID_PATTERN
from utils.git_blobs import GitBlobError, read_committed_blob
from utils.yaml_utils import UniqueKeySafeLoader


class OracleRegistryError(ValueError):
    """The reviewed oracle registry cannot be trusted or materialized."""


class OracleSpecEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    oracle_id: str = Field(pattern=r"^[a-z][a-z0-9_]+$")
    weakness_id: str = Field(pattern=WEAKNESS_ID_PATTERN)
    family_key: str = Field(pattern=FAMILY_KEY_PATTERN)
    technology: str | None = Field(default=None, min_length=1)
    status: Literal["accepted"]
    observable_kind: Literal[
        "response", "timing", "out_of_band", "state", "execution"
    ]
    observation: str = Field(min_length=1)
    success_criteria: str = Field(min_length=1)
    baseline_required: bool = False
    threshold: str | None = Field(default=None, min_length=1)
    correlation_requirement: str | None = Field(default=None, min_length=1)
    applicability_notes: str | None = Field(default=None, min_length=1)
    source_ref: str = Field(min_length=1)
    source_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reviewed_by: str = Field(min_length=1)
    reviewed_at: datetime

    @model_validator(mode="after")
    def reviewed_at_has_timezone(self) -> Self:
        if self.reviewed_at.tzinfo is None or self.reviewed_at.utcoffset() is None:
            raise ValueError("reviewed_at must include timezone")
        return self


class OracleRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    oracles: list[OracleSpecEntry]

    @model_validator(mode="after")
    def oracle_ids_are_unique(self) -> Self:
        identifiers = [entry.oracle_id for entry in self.oracles]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("duplicate oracle_id in oracle registry")
        return self


def _read_registry(path: Path) -> OracleRegistry:
    if not path.is_file():
        raise OracleRegistryError(f"{path}: oracle registry does not exist")
    try:
        raw = yaml.load(
            path.read_text(encoding="utf-8"), Loader=UniqueKeySafeLoader
        )
        return OracleRegistry.model_validate(raw)
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError) as exc:
        raise OracleRegistryError(f"{path}: invalid oracle registry: {exc}") from exc


def _verified_source(entry: OracleSpecEntry, repo_root: Path) -> None:
    try:
        committed = read_committed_blob(repo_root, entry.source_ref)
    except GitBlobError as exc:
        raise OracleRegistryError(
            f"{entry.oracle_id}: {exc}"
        ) from exc
    if committed.sha256 != entry.source_hash:
        raise OracleRegistryError(
            f"{entry.oracle_id}: source_hash mismatch for "
            f"{entry.source_ref}; expected {entry.source_hash}, got "
            f"{committed.sha256}"
        )


def load_oracle_specs(
    sink: GraphSink,
    registry_path: str | Path,
    repo_root: str | Path,
) -> dict[str, int]:
    registry = _read_registry(Path(registry_path))
    root = Path(repo_root)
    for entry in registry.oracles:
        _verified_source(entry, root)
        if sink.get_node("Weakness", "weaknessId", entry.weakness_id) is None:
            raise OracleRegistryError(
                f"{entry.oracle_id}: unknown Weakness {entry.weakness_id}"
            )
        if sink.get_node("PayloadFamily", "key", entry.family_key) is None:
            raise OracleRegistryError(
                f"{entry.oracle_id}: unknown PayloadFamily {entry.family_key}"
            )
        signal = DetectionSignal(
            key=entry.oracle_id,
            name=entry.oracle_id.replace("_", " "),
            trustLevel="accepted",
            observableKind=entry.observable_kind,
            observation=entry.observation,
            successCriteria=entry.success_criteria,
            baselineRequired=entry.baseline_required,
            threshold=entry.threshold,
            correlationRequirement=entry.correlation_requirement,
            applicabilityNotes=entry.applicability_notes,
            weaknessId=entry.weakness_id,
            familyKey=entry.family_key,
            technology=entry.technology,
            sourceRef=entry.source_ref,
            sourceHash=entry.source_hash,
            reviewedBy=entry.reviewed_by,
            reviewedAt=entry.reviewed_at.isoformat(),
        )
        sink.merge_node("DetectionSignal", "key", signal.to_props())
        sink.merge_rel(
            "DetectionSignal", "key", entry.oracle_id,
            "TARGETS", "Weakness", "weaknessId", entry.weakness_id,
            {"source": "oracle-registry", "trustLevel": "accepted"},
        )
        sink.merge_rel(
            "DetectionSignal", "key", entry.oracle_id,
            "APPLIES_TO_FAMILY", "PayloadFamily", "key", entry.family_key,
            {"source": "oracle-registry", "trustLevel": "accepted"},
        )
        if entry.technology:
            if sink.get_node("Technology", "name", entry.technology) is None:
                raise OracleRegistryError(
                    f"{entry.oracle_id}: unknown Technology {entry.technology}"
                )
            sink.merge_rel(
                "DetectionSignal", "key", entry.oracle_id,
                "ON_TECH", "Technology", "name", entry.technology,
                {"source": "oracle-registry"},
            )
    return {"oracles": len(registry.oracles), "accepted": len(registry.oracles)}
