"""Strict durable events for extracted payload review."""

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
    PAYLOAD_EVENT_ID_PATTERN,
    PAYLOAD_FAMILY_KEY_PATTERN,
    PAYLOAD_PROPOSAL_ID_PATTERN,
    WEAKNESS_ID_PATTERN,
)


class PayloadModel(BaseModel):
    """Strict model that preserves executable strings byte-for-byte."""

    model_config = ConfigDict(extra="forbid")


class PayloadProposalSnapshot(PayloadModel):
    weaknessId: str = Field(pattern=WEAKNESS_ID_PATTERN)
    payloadValue: str = Field(min_length=1)
    familyKey: str = Field(pattern=PAYLOAD_FAMILY_KEY_PATTERN)
    familyName: str = Field(min_length=1)
    technology: str | None = Field(default=None, min_length=1)
    rationale: str = Field(min_length=1)
    sourceRef: str = Field(min_length=1)
    sourceExcerpt: str = Field(min_length=1)
    producerKind: Literal["human", "ai", "rule"]
    producerName: str = Field(min_length=1)
    producerVersion: str | None = Field(default=None, min_length=1)

    @field_validator(
        "weaknessId",
        "familyKey",
        "familyName",
        "technology",
        "rationale",
        "sourceRef",
        "producerName",
        "producerVersion",
        mode="before",
    )
    @classmethod
    def strip_metadata(cls, value):
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def extraction_and_producer_are_grounded(self) -> Self:
        if not self.payloadValue.strip():
            raise ValueError("payloadValue must not be blank")
        if not self.sourceExcerpt.strip():
            raise ValueError("sourceExcerpt must not be blank")
        if self.payloadValue not in self.sourceExcerpt:
            raise ValueError(
                "payloadValue must occur exactly in sourceExcerpt"
            )
        if self.producerKind != "human" and not self.producerVersion:
            raise ValueError(
                "ai and rule producers require producerVersion"
            )
        return self


class ValidationRecord(PayloadModel):
    revision: int = Field(ge=1)
    result: Literal["passed", "failed", "inconclusive"]
    environment: str = Field(min_length=1)
    targetRef: str = Field(min_length=1)
    targetHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    executionRef: str = Field(min_length=1)
    executionHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    observedOutcome: str = Field(min_length=1)
    evidenceRef: str = Field(min_length=1)
    evidenceHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    comment: str | None = Field(default=None, min_length=1)

    @field_validator(
        "environment",
        "targetRef",
        "executionRef",
        "observedOutcome",
        "evidenceRef",
        "comment",
        mode="before",
    )
    @classmethod
    def strip_text(cls, value):
        return value.strip() if isinstance(value, str) else value


class PayloadEventBase(PayloadModel):
    schemaVersion: Literal[1]
    eventId: str = Field(pattern=PAYLOAD_EVENT_ID_PATTERN)
    proposalId: str = Field(pattern=PAYLOAD_PROPOSAL_ID_PATTERN)
    occurredAt: datetime
    actor: str = Field(min_length=1)
    actorType: Literal["human", "ai", "rule"]

    @field_validator("actor", mode="before")
    @classmethod
    def strip_actor(cls, value):
        return value.strip() if isinstance(value, str) else value

    @field_validator("occurredAt", mode="before")
    @classmethod
    def occurred_at_has_timezone(cls, value):
        if isinstance(value, datetime):
            return value
        if not isinstance(value, str):
            raise ValueError(
                "occurredAt must be an ISO-8601 timestamp "
                "with timezone"
            )
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

    @model_validator(mode="after")
    def parsed_timestamp_has_timezone(self) -> Self:
        if (
            self.occurredAt.tzinfo is None
            or self.occurredAt.utcoffset() is None
        ):
            raise ValueError("occurredAt must include timezone")
        return self


class ProposePayloadEvent(PayloadEventBase):
    eventType: Literal["propose"]
    snapshot: PayloadProposalSnapshot


class HumanPayloadEvent(PayloadEventBase):
    actorType: Literal["human"]


class RequestPayloadChangesEvent(HumanPayloadEvent):
    eventType: Literal["request_changes"]
    comment: str = Field(min_length=1)

    @field_validator("comment", mode="before")
    @classmethod
    def strip_comment(cls, value):
        return value.strip() if isinstance(value, str) else value


class RevisePayloadEvent(PayloadEventBase):
    eventType: Literal["revise"]
    response: str = Field(min_length=1)
    snapshot: PayloadProposalSnapshot

    @field_validator("response", mode="before")
    @classmethod
    def strip_response(cls, value):
        return value.strip() if isinstance(value, str) else value


class RecordPayloadValidationEvent(HumanPayloadEvent):
    eventType: Literal["record_validation"]
    validation: ValidationRecord


class ApprovePayloadEvent(HumanPayloadEvent):
    eventType: Literal["approve"]
    comment: str | None = Field(default=None, min_length=1)

    @field_validator("comment", mode="before")
    @classmethod
    def strip_comment(cls, value):
        return value.strip() if isinstance(value, str) else value


class RejectPayloadEvent(HumanPayloadEvent):
    eventType: Literal["reject"]
    comment: str | None = Field(default=None, min_length=1)

    @field_validator("comment", mode="before")
    @classmethod
    def strip_comment(cls, value):
        return value.strip() if isinstance(value, str) else value


PayloadEvent = Annotated[
    Union[
        ProposePayloadEvent,
        RequestPayloadChangesEvent,
        RevisePayloadEvent,
        RecordPayloadValidationEvent,
        ApprovePayloadEvent,
        RejectPayloadEvent,
    ],
    Field(discriminator="eventType"),
]
