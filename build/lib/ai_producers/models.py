from __future__ import annotations

from typing import Any, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)

from utils.identifiers import WEAKNESS_ID_PATTERN


class AIContractError(ValueError):
    """Raised before requesting an impossible strict output schema."""


def compact_validation_error(error: Exception) -> str:
    if not hasattr(error, "errors"):
        return type(error).__name__
    details = error.errors(
        include_url=False,
        include_context=False,
        include_input=False,
    )
    messages = []
    for item in details[:8]:
        location = ".".join(
            str(part)[:64] for part in item["loc"][:8]
        )
        message = str(item["msg"])[:256]
        messages.append(f"{location}: {message}")
    return "; ".join(messages)


class _StrictAIModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RelationAIItem(_StrictAIModel):
    predicate: str
    objectWeaknessId: str = Field(pattern=WEAKNESS_ID_PATTERN)
    dimension: str | None
    rationale: str = Field(min_length=1)
    evidenceKeys: list[str] = Field(min_length=1)

    @field_validator("rationale")
    @classmethod
    def strip_rationale(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("rationale must not be blank")
        return value

    @field_validator("evidenceKeys")
    @classmethod
    def evidence_keys_are_unique_and_nonempty(
        cls,
        values: list[str],
    ) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("evidence keys must not be blank")
        if len(set(values)) != len(values):
            raise ValueError("evidence keys must not contain duplicates")
        return values

    @model_validator(mode="after")
    def predicate_matches_dimension(self) -> Self:
        if self.predicate == "CHILD_OF":
            if self.dimension is not None:
                self.dimension = None
        elif self.predicate == "SIMILAR_TO":
            if (
                self.dimension is None
                or not self.dimension
                or not self.dimension[0].islower()
                or not all(
                    character.islower()
                    or character.isdigit()
                    or character == "_"
                    for character in self.dimension
                )
            ):
                raise ValueError(
                    "SIMILAR_TO requires a lower_snake_case dimension"
                )
        else:
            raise ValueError("unsupported relation predicate")
        return self


class RelationAIResponse(_StrictAIModel):
    proposals: list[RelationAIItem]

    @model_validator(mode="after")
    def proposals_are_bounded_and_unique(
        self,
        info: ValidationInfo,
    ) -> Self:
        max_items = (info.context or {}).get("max_items")
        if not isinstance(max_items, int) or max_items <= 0:
            raise ValueError("positive max_items validation context is required")
        if len(self.proposals) > max_items:
            raise ValueError(f"response may contain at most {max_items} proposals")
        identities = [
            (item.predicate, item.objectWeaknessId, item.dimension)
            for item in self.proposals
        ]
        if len(set(identities)) != len(identities):
            raise ValueError("response contains duplicate relation proposals")
        return self


class PayloadAIItem(_StrictAIModel):
    payloadValue: str = Field(min_length=1)
    sourceExcerpt: str = Field(min_length=1)
    rationale: str = Field(min_length=1)

    @field_validator("payloadValue", "sourceExcerpt")
    @classmethod
    def exact_value_is_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("exact extracted strings must not be blank")
        return value

    @field_validator("rationale")
    @classmethod
    def strip_rationale(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("rationale must not be blank")
        return value

    @model_validator(mode="after")
    def payload_occurs_in_excerpt(self) -> Self:
        if self.payloadValue not in self.sourceExcerpt:
            raise ValueError(
                "payloadValue must occur exactly in sourceExcerpt"
            )
        return self


class PayloadAIResponse(_StrictAIModel):
    extractions: list[PayloadAIItem]

    @model_validator(mode="after")
    def extractions_are_bounded_and_unique(
        self,
        info: ValidationInfo,
    ) -> Self:
        max_items = (info.context or {}).get("max_items")
        if not isinstance(max_items, int) or max_items <= 0:
            raise ValueError("positive max_items validation context is required")
        if len(self.extractions) > max_items:
            raise ValueError(
                f"response may contain at most {max_items} extractions"
            )
        identities = [
            (item.payloadValue, item.sourceExcerpt)
            for item in self.extractions
        ]
        if len(set(identities)) != len(identities):
            raise ValueError("response contains duplicate payload extractions")
        return self


def _positive_max_items(max_items: int) -> int:
    if (
        isinstance(max_items, bool)
        or not isinstance(max_items, int)
        or max_items <= 0
    ):
        raise AIContractError("max_items must be a positive integer")
    return max_items


def relation_response_schema(
    candidate_ids: list[str],
    dimensions: list[str],
    max_items: int,
) -> dict[str, Any]:
    candidate_enum = sorted(set(candidate_ids))
    dimension_enum = sorted(set(dimensions))
    if not candidate_enum:
        raise AIContractError("relation schema needs at least one candidate")
    dimension_variants: list[dict[str, Any]] = [
        {"type": "null"}
    ]
    if dimension_enum:
        dimension_variants.insert(
            0,
            {
                "type": "string",
                "enum": dimension_enum,
            },
        )
    return {
        "type": "object",
        "properties": {
            "proposals": {
                "type": "array",
                "maxItems": _positive_max_items(max_items),
                "items": {
                    "type": "object",
                    "properties": {
                        "predicate": {
                            "type": "string",
                            "enum": ["CHILD_OF", "SIMILAR_TO"],
                        },
                        "objectWeaknessId": {
                            "type": "string",
                            "enum": candidate_enum,
                        },
                        "dimension": {
                            "anyOf": dimension_variants
                        },
                        "rationale": {"type": "string", "minLength": 1},
                        "evidenceKeys": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string", "minLength": 1},
                        },
                    },
                    "required": [
                        "predicate",
                        "objectWeaknessId",
                        "dimension",
                        "rationale",
                        "evidenceKeys",
                    ],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["proposals"],
        "additionalProperties": False,
    }


def payload_response_schema(max_items: int) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "extractions": {
                "type": "array",
                "maxItems": _positive_max_items(max_items),
                "items": {
                    "type": "object",
                    "properties": {
                        "payloadValue": {"type": "string", "minLength": 1},
                        "sourceExcerpt": {"type": "string", "minLength": 1},
                        "rationale": {"type": "string", "minLength": 1},
                    },
                    "required": [
                        "payloadValue",
                        "sourceExcerpt",
                        "rationale",
                    ],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["extractions"],
        "additionalProperties": False,
    }


class WeaknessIngestAIResponse(_StrictAIModel):
    name: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    technologies: list[str] = Field(default_factory=list)
    declaredBy: str = Field(default="Research", min_length=1)
    sourceType: str = Field(default="advisory", min_length=1)
    suggestedNamespace: str = Field(default="LOCAL", min_length=1)


def weakness_ingest_response_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "name": {"type": "string", "minLength": 1},
            "summary": {"type": "string", "minLength": 1},
            "technologies": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
            },
            "declaredBy": {"type": "string", "minLength": 1},
            "sourceType": {"type": "string", "minLength": 1},
            "suggestedNamespace": {"type": "string", "minLength": 1},
        },
        "required": [
            "name",
            "summary",
            "technologies",
            "declaredBy",
            "sourceType",
            "suggestedNamespace",
        ],
        "additionalProperties": False,
    }
