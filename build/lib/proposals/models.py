"""Strict durable event models for relation proposal review."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Self, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from utils.identifiers import (
    RELATION_EVENT_ID_PATTERN,
    RELATION_PROPOSAL_ID_PATTERN,
    WEAKNESS_ID_PATTERN,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


class Evidence(StrictModel):
    sourceRef: str = Field(min_length=1)
    excerpt: str = Field(min_length=1)


class RetrievalMetadata(StrictModel):
    score: float = Field(ge=-1, le=1)
    scoreType: Literal["cosine_similarity"]
    candidateRank: int = Field(ge=1)
    candidateSetSize: int = Field(ge=1)
    embeddingModel: str = Field(min_length=1)
    subjectTextHash: str = Field(pattern=r"^[0-9a-f]{64}$")
    objectTextHash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def rank_is_within_candidate_set(self) -> Self:
        if self.candidateRank > self.candidateSetSize:
            raise ValueError(
                "candidateRank must not exceed candidateSetSize"
            )
        return self


class ProposalSnapshot(StrictModel):
    subjectWeaknessId: str = Field(pattern=WEAKNESS_ID_PATTERN)
    predicate: Literal["CHILD_OF", "SIMILAR_TO"]
    objectWeaknessId: str = Field(pattern=WEAKNESS_ID_PATTERN)
    dimension: str | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_]*$",
    )
    rationale: str = Field(min_length=1)
    evidence: list[Evidence] = Field(min_length=1)
    producerKind: Literal["human", "ai", "rule"]
    producerName: str = Field(min_length=1)
    producerVersion: str | None = Field(default=None, min_length=1)
    retrieval: RetrievalMetadata | None = None

    @model_validator(mode="after")
    def machine_producer_has_version(self) -> Self:
        if self.producerKind != "human" and not self.producerVersion:
            raise ValueError(
                "ai and rule producers require producerVersion"
            )
        if self.producerKind == "ai" and self.retrieval is None:
            raise ValueError("ai relation proposals require retrieval metadata")
        if self.producerKind != "ai" and self.retrieval is not None:
            raise ValueError("retrieval metadata is only valid for ai proposals")
        return self


class EventBase(StrictModel):
    schemaVersion: Literal[1]
    eventId: str = Field(pattern=RELATION_EVENT_ID_PATTERN)
    proposalId: str = Field(pattern=RELATION_PROPOSAL_ID_PATTERN)
    occurredAt: datetime
    actor: str = Field(min_length=1)
    actorType: Literal["human", "ai", "rule"]

    @field_validator("occurredAt", mode="before")
    @classmethod
    def occurred_at_has_explicit_timezone(cls, value):
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise ValueError(
                    "occurredAt must be an ISO-8601 timestamp "
                    "with timezone"
                ) from exc
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("occurredAt must include timezone")
            return parsed
        return value

    @model_validator(mode="after")
    def parsed_timestamp_has_timezone(self) -> Self:
        if (
            self.occurredAt.tzinfo is None
            or self.occurredAt.utcoffset() is None
        ):
            raise ValueError("occurredAt must include timezone")
        return self


class ProposeEvent(EventBase):
    eventType: Literal["propose"]
    snapshot: ProposalSnapshot


class HumanReviewEvent(EventBase):
    actorType: Literal["human"]


class RequestChangesEvent(HumanReviewEvent):
    eventType: Literal["request_changes"]
    comment: str = Field(min_length=1)


class ReviseEvent(EventBase):
    eventType: Literal["revise"]
    response: str = Field(min_length=1)
    snapshot: ProposalSnapshot


class ApproveEvent(HumanReviewEvent):
    eventType: Literal["approve"]
    comment: str | None = Field(default=None, min_length=1)


class RejectEvent(HumanReviewEvent):
    eventType: Literal["reject"]
    comment: str | None = Field(default=None, min_length=1)


class RetractEvent(HumanReviewEvent):
    eventType: Literal["retract"]
    reason: str = Field(min_length=1)


RelationEvent = Annotated[
    Union[
        ProposeEvent,
        RequestChangesEvent,
        ReviseEvent,
        ApproveEvent,
        RejectEvent,
        RetractEvent,
    ],
    Field(discriminator="eventType"),
]
