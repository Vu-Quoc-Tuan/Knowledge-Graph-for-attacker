from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import (
    AnyUrl,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from db.sink import GraphSink
from utils.yaml_utils import UniqueKeySafeLoader
from schema.models import Technology, WEAKNESS_ID_PATTERN, Weakness
from utils.git_blobs import (
    GitBlobError,
    git_worktree_root,
    read_committed_blob,
)


class LocalRegistryError(ValueError):
    """The configured local registry cannot be loaded without losing integrity."""


class LocalWeaknessEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    weakness_id: str = Field(pattern=WEAKNESS_ID_PATTERN)
    namespace: str = Field(pattern=r"^[A-Z][A-Z0-9]*$")
    name: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    lifecycle_status: Literal["proposed", "accepted", "deprecated"]
    superseded_by: str | None = Field(default=None, pattern=WEAKNESS_ID_PATTERN)
    source_type: str = Field(min_length=1)
    source_url: AnyUrl | None = None
    source_title: str | None = Field(default=None, min_length=1)
    source_excerpt: str | None = Field(default=None, min_length=1)
    source_hash: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    source_snapshot: str | None = Field(
        default=None,
        pattern=(
            r"^registry/source_snapshots/objects/"
            r"[0-9a-f]{64}\.[a-z0-9]{1,10}$"
        ),
    )
    declared_by: str = Field(min_length=1)
    created_at: str | None = Field(default=None, min_length=1)
    updated_at: str | None = Field(default=None, min_length=1)
    technologies: list[str] = Field(default_factory=list)

    @field_validator("technologies")
    @classmethod
    def technologies_are_nonempty_and_unique(
        cls, technologies: list[str]
    ) -> list[str]:
        if any(not technology for technology in technologies):
            raise ValueError("technologies must not contain empty names")
        if len(set(technologies)) != len(technologies):
            raise ValueError("technologies must not contain duplicates")
        return technologies

    @model_validator(mode="after")
    def identity_is_local_and_namespaced(self) -> Self:
        if self.weakness_id.startswith("CWE-"):
            raise ValueError(
                "local registry may not declare the reserved CWE namespace"
            )
        prefix = self.weakness_id.split("-", 1)[0]
        if prefix != self.namespace:
            raise ValueError(
                "namespace must match the weakness_id prefix"
            )
        if (self.source_hash is None) != (self.source_snapshot is None):
            raise ValueError(
                "source_hash and source_snapshot must be provided together"
            )
        if self.source_snapshot is not None and self.source_excerpt is None:
            raise ValueError(
                "snapshot-backed sources require source_excerpt"
            )
        return self


class LocalWeaknessRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    weaknesses: list[LocalWeaknessEntry]

    @model_validator(mode="after")
    def weakness_ids_are_unique(self) -> Self:
        weakness_ids = [
            entry.weakness_id for entry in self.weaknesses
        ]
        if len(set(weakness_ids)) != len(weakness_ids):
            raise ValueError("duplicate weakness_id in local registry")
        return self


def _read_registry(path: Path) -> LocalWeaknessRegistry:
    if not path.is_file():
        raise LocalRegistryError(
            f"{path}: local weakness registry does not exist"
        )
    try:
        raw = yaml.load(
            path.read_text(encoding="utf-8"),
            Loader=UniqueKeySafeLoader,
        )
    except (OSError, UnicodeError) as exc:
        raise LocalRegistryError(
            f"{path}: cannot read local weakness registry: {exc}"
        ) from exc
    except yaml.YAMLError as exc:
        raise LocalRegistryError(
            f"{path}: invalid YAML in local weakness registry: {exc}"
        ) from exc

    if not isinstance(raw, dict):
        raise LocalRegistryError(
            f"{path}: local weakness registry root must be a mapping"
        )
    try:
        return LocalWeaknessRegistry.model_validate(raw)
    except ValidationError as exc:
        raise LocalRegistryError(
            f"{path}: invalid local weakness registry: {exc}"
        ) from exc


def load_local_weaknesses(
    sink: GraphSink, registry_path: str | Path
) -> dict[str, int]:
    """Validate the complete registry, then materialize its asserted graph."""

    path = Path(registry_path)
    registry = _read_registry(path)
    snapshot_entries = [
        entry
        for entry in registry.weaknesses
        if entry.source_snapshot is not None
    ]
    if snapshot_entries:
        try:
            repo_root = git_worktree_root(path)
            for entry in snapshot_entries:
                if entry.source_snapshot is None:
                    raise LocalRegistryError(
                        f"{entry.weakness_id}: source snapshot is required"
                    )
                committed = read_committed_blob(
                    repo_root,
                    entry.source_snapshot,
                )
                if committed.sha256 != entry.source_hash:
                    raise LocalRegistryError(
                        f"{entry.weakness_id}: source_hash mismatch for "
                        f"{entry.source_snapshot}; expected "
                        f"{entry.source_hash}, got {committed.sha256}"
                    )
        except GitBlobError as exc:
            raise LocalRegistryError(str(exc)) from exc
    counts = {
        "weaknesses": len(registry.weaknesses),
        "technology_edges": 0,
        "proposed": 0,
        "accepted": 0,
        "deprecated": 0,
    }

    for entry in registry.weaknesses:
        weakness = Weakness(
            weaknessId=entry.weakness_id,
            namespace=entry.namespace,
            name=entry.name,
            summary=entry.summary,
            lifecycleStatus=entry.lifecycle_status,
            supersededBy=entry.superseded_by,
            origin="local",
            sourceType=entry.source_type,
            sourceUrl=(
                str(entry.source_url) if entry.source_url else None
            ),
            sourceTitle=entry.source_title,
            sourceExcerpt=entry.source_excerpt,
            sourceHash=entry.source_hash,
            sourceSnapshot=entry.source_snapshot,
            declaredBy=entry.declared_by,
            createdAt=entry.created_at,
            updatedAt=entry.updated_at,
        )
        sink.merge_node(
            "Weakness", "weaknessId", weakness.to_props()
        )
        counts[entry.lifecycle_status] += 1

        for technology_name in entry.technologies:
            technology = Technology(name=technology_name)
            sink.merge_node(
                "Technology", "name", technology.to_props()
            )
            sink.merge_rel(
                "Weakness",
                "weaknessId",
                entry.weakness_id,
                "AFFECTS_TECHNOLOGY",
                "Technology",
                "name",
                technology_name,
                {
                    "source": "local-registry",
                    "assertedBy": entry.declared_by,
                },
            )
            counts["technology_edges"] += 1

    return counts
