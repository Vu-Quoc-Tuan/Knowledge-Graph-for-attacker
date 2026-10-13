"""Load reusable scenario fragments catalog into the graph sink."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from db.sink import GraphSink
from schema.models import ScenarioFragment
from utils.yaml_utils import UniqueKeySafeLoader


class FragmentRegistryError(ValueError):
    """Raised when the fragment registry fails validation."""


class FragmentEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    fragment_id: str = Field(pattern=r"^FRAG-[A-Za-z0-9_-]+$")
    kind: Literal["setup", "input_mutation", "trigger", "oracle", "cleanup"]
    name: str = Field(min_length=1)
    description: str = Field(default="", min_length=0)
    requirements: list[str] = Field(default_factory=list)
    action_template: str = Field(min_length=1)


class FragmentRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    fragments: list[FragmentEntry]


def read_fragment_registry(path: Path) -> FragmentRegistry:
    if not path.is_file():
        raise FragmentRegistryError(f"{path}: fragment registry does not exist")
    try:
        raw = yaml.load(
            path.read_text(encoding="utf-8"),
            Loader=UniqueKeySafeLoader,
        )
    except (OSError, UnicodeError) as exc:
        raise FragmentRegistryError(f"{path}: cannot read fragment registry: {exc}") from exc
    except yaml.YAMLError as exc:
        raise FragmentRegistryError(f"{path}: invalid YAML in fragment registry: {exc}") from exc

    if not isinstance(raw, dict):
        raise FragmentRegistryError(f"{path}: fragment registry root must be a mapping")
    try:
        return FragmentRegistry.model_validate(raw)
    except ValidationError as exc:
        raise FragmentRegistryError(f"{path}: invalid fragment registry: {exc}") from exc


def load_fragments(sink: GraphSink, registry_path: str | Path) -> dict[str, int]:
    path = Path(registry_path)
    registry = read_fragment_registry(path)

    counts = {
        "fragments": len(registry.fragments),
        "setup": 0,
        "input_mutation": 0,
        "trigger": 0,
        "oracle": 0,
        "cleanup": 0,
    }

    for entry in registry.fragments:
        fragment_node = ScenarioFragment(
            fragmentId=entry.fragment_id,
            kind=entry.kind,
            name=entry.name,
            description=entry.description,
            requirements=entry.requirements,
            actionTemplate=entry.action_template,
        )
        sink.merge_node("ScenarioFragment", "fragmentId", fragment_node.to_props())
        counts[entry.kind] += 1

    return counts
