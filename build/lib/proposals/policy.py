"""Strict parsing for the version-controlled relation policy."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from utils.yaml_utils import UniqueKeySafeLoader


SUPPORTED_PREDICATES = frozenset({"CHILD_OF", "SIMILAR_TO"})


class RelationPolicyError(ValueError):
    """The relation policy cannot be loaded without losing integrity."""


class PredicatePolicy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    symmetric: bool
    dimension_required: bool
    allowed_dimensions: list[
        str
    ] = Field(default_factory=list)

    @model_validator(mode="after")
    def dimensions_match_policy(self) -> Self:
        if any(
            not dimension
            or not dimension[0].islower()
            or not all(
                character.islower()
                or character.isdigit()
                or character == "_"
                for character in dimension
            )
            for dimension in self.allowed_dimensions
        ):
            raise ValueError(
                "allowed dimensions must use lower_snake_case"
            )
        if len(set(self.allowed_dimensions)) != len(
            self.allowed_dimensions
        ):
            raise ValueError(
                "allowed dimensions must not contain duplicates"
            )
        if self.dimension_required and not self.allowed_dimensions:
            raise ValueError(
                "a dimension-required predicate needs at least one dimension"
            )
        if not self.dimension_required and self.allowed_dimensions:
            raise ValueError(
                "dimensions are forbidden when dimension_required is false"
            )
        return self


class RelationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    predicates: dict[str, PredicatePolicy]

    @model_validator(mode="after")
    def predicates_are_supported_and_coherent(self) -> Self:
        if not self.predicates:
            raise ValueError(
                "relation policy requires at least one predicate"
            )
        unsupported = sorted(
            set(self.predicates) - SUPPORTED_PREDICATES
        )
        if unsupported:
            raise ValueError(
                f"unsupported predicate(s): {unsupported}"
            )

        child = self.predicates.get("CHILD_OF")
        if child is not None:
            if child.symmetric:
                raise ValueError("CHILD_OF must be directional")
            if child.dimension_required:
                raise ValueError("CHILD_OF must not require a dimension")

        similar = self.predicates.get("SIMILAR_TO")
        if similar is not None:
            if not similar.symmetric:
                raise ValueError("SIMILAR_TO must be symmetric")
            if not similar.dimension_required:
                raise ValueError(
                    "SIMILAR_TO must require a dimension"
                )
        return self


def read_relation_policy(
    path: str | Path,
) -> RelationPolicy:
    source = Path(path)
    if not source.is_file():
        raise RelationPolicyError(
            f"{source}: relation policy does not exist"
        )
    try:
        raw = yaml.load(
            source.read_text(encoding="utf-8"),
            Loader=UniqueKeySafeLoader,
        )
    except (OSError, UnicodeError) as exc:
        raise RelationPolicyError(
            f"{source}: cannot read relation policy: {exc}"
        ) from exc
    except yaml.YAMLError as exc:
        raise RelationPolicyError(
            f"{source}: invalid YAML in relation policy: {exc}"
        ) from exc

    if not isinstance(raw, dict):
        raise RelationPolicyError(
            f"{source}: relation policy root must be a mapping"
        )
    try:
        return RelationPolicy.model_validate(raw)
    except ValidationError as exc:
        raise RelationPolicyError(
            f"{source}: invalid relation policy: {exc}"
        ) from exc
