from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from pydantic import ValidationError

from ai_producers.models import (
    PayloadAIResponse,
    compact_validation_error,
    payload_response_schema,
)
from ai_producers.prompts import (
    payload_create_messages,
    payload_revision_messages,
)
from ai_producers.provider import AISettings, StructuredChatProvider
from ai_producers.source import SourceDocument, read_tracked_source
from db.sink import GraphSink
from proposals.payload_log import payload_fingerprint
from proposals.payload_models import (
    PayloadProposalSnapshot,
    ProposePayloadEvent,
    RequestPayloadChangesEvent,
    RevisePayloadEvent,
)
from proposals.payload_service import PayloadEventService


class PayloadProducerError(ValueError):
    """Raised when AI payload output is not a grounded extraction."""



@dataclass(frozen=True)
class PayloadPreview:
    weakness_id: str
    source_ref: str
    snapshots: tuple[PayloadProposalSnapshot, ...]



class PayloadAIProducer:
    def __init__(
        self,
        sink: GraphSink,
        provider: StructuredChatProvider,
        service: PayloadEventService,
        settings: AISettings,
    ) -> None:
        self.sink = sink
        self.provider = provider
        self.service = service
        self.settings = settings

    def _source(self, source_ref: str) -> SourceDocument:
        return read_tracked_source(
            self.service.repo_root,
            source_ref,
            self.settings.max_source_chars,
        )

    def _require_weakness(self, weakness_id: str) -> None:
        if (
            self.sink.get_node(
                "Weakness",
                "weaknessId",
                weakness_id,
            )
            is None
        ):
            raise PayloadProducerError(
                f"unknown Weakness: {weakness_id}"
            )

    def _snapshots(
        self,
        raw_response: Mapping[str, object],
        *,
        weakness_id: str,
        family_key: str,
        family_name: str,
        technology: str | None,
        document: SourceDocument,
        exclude_proposal_id: str | None = None,
    ) -> tuple[PayloadProposalSnapshot, ...]:
        try:
            response = PayloadAIResponse.model_validate(
                raw_response,
                context={
                    "max_items": self.settings.max_payload_proposals
                },
            )
        except ValidationError as exc:
            raise PayloadProducerError(
                "invalid AI payload response: "
                f"{compact_validation_error(exc)}"
            ) from exc
        snapshots: list[PayloadProposalSnapshot] = []
        for extraction in response.extractions:
            if extraction.sourceExcerpt not in document.content:
                raise PayloadProducerError(
                    "AI sourceExcerpt does not occur exactly in source"
                )
            snapshots.append(
                PayloadProposalSnapshot(
                    weaknessId=weakness_id,
                    payloadValue=extraction.payloadValue,
                    familyKey=family_key,
                    familyName=family_name,
                    technology=technology,
                    rationale=extraction.rationale,
                    sourceRef=document.source_ref,
                    sourceExcerpt=extraction.sourceExcerpt,
                    producerKind="ai",
                    producerName=self.settings.producer_name,
                    producerVersion=self.settings.payload_producer_version,
                )
            )
        self._preflight_fingerprints(
            snapshots,
            exclude_proposal_id=exclude_proposal_id,
        )
        return tuple(snapshots)

    def _preflight_fingerprints(
        self,
        snapshots: Sequence[PayloadProposalSnapshot],
        *,
        exclude_proposal_id: str | None = None,
    ) -> None:
        fingerprints = [
            payload_fingerprint(snapshot) for snapshot in snapshots
        ]
        if len(set(fingerprints)) != len(fingerprints):
            raise PayloadProducerError(
                "AI response contains duplicate payload fingerprints"
            )
        for state in self.service.list_proposals():
            if state.proposalId == exclude_proposal_id:
                continue
            if (
                state.fingerprint in fingerprints
                and state.status != "rejected"
            ):
                raise PayloadProducerError(
                    "payload fingerprint is already active or accepted "
                    f"as {state.proposalId}"
                )

    def preview(
        self,
        *,
        weakness_id: str,
        family_key: str,
        family_name: str,
        source_ref: str,
        technology: str | None = None,
    ) -> PayloadPreview:
        self._require_weakness(weakness_id)
        document = self._source(source_ref)
        classification = {
            "weaknessId": weakness_id,
            "familyKey": family_key,
            "familyName": family_name,
            "technology": technology,
        }
        raw = self.provider.structured_chat(
            payload_create_messages(
                classification,
                document.source_ref,
                document.content,
            ),
            schema_name="payload_extractions",
            schema=payload_response_schema(
                self.settings.max_payload_proposals
            ),
        )
        snapshots = self._snapshots(
            raw,
            weakness_id=weakness_id,
            family_key=family_key,
            family_name=family_name,
            technology=technology,
            document=document,
        )
        return PayloadPreview(
            weakness_id=weakness_id,
            source_ref=document.source_ref,
            snapshots=snapshots,
        )

    def write(
        self,
        *,
        weakness_id: str,
        family_key: str,
        family_name: str,
        source_ref: str,
        technology: str | None = None,
    ) -> list[ProposePayloadEvent]:
        preview = self.preview(
            weakness_id=weakness_id,
            family_key=family_key,
            family_name=family_name,
            source_ref=source_ref,
            technology=technology,
        )
        if not preview.snapshots:
            return []
        return self.service.create_many(
            preview.snapshots,
            actor=self.settings.producer_name,
            actor_type="ai",
        )

    def _revision_inputs(self, proposal_id: str):
        state = self.service.get(proposal_id)
        if state.status != "changes_requested":
            raise PayloadProducerError(
                f"{proposal_id}: AI revision requires changes_requested"
            )
        if state.snapshot.producerKind != "ai":
            raise PayloadProducerError(
                f"{proposal_id}: only AI proposals can be AI-revised"
            )
        review = next(
            (
                event
                for event in reversed(state.events)
                if isinstance(event, RequestPayloadChangesEvent)
            ),
            None,
        )
        if review is None:
            raise PayloadProducerError(
                f"{proposal_id}: missing human review comment"
            )
        self._require_weakness(state.snapshot.weaknessId)
        document = self._source(state.snapshot.sourceRef)
        return state, review, document

    def preview_revision(
        self,
        proposal_id: str,
    ) -> PayloadPreview:
        state, review, document = self._revision_inputs(proposal_id)
        raw = self.provider.structured_chat(
            payload_revision_messages(
                state.snapshot.model_dump(mode="json"),
                review.comment,
                document.source_ref,
                document.content,
            ),
            schema_name="payload_revision",
            schema=payload_response_schema(1),
        )
        snapshots = self._snapshots(
            raw,
            weakness_id=state.snapshot.weaknessId,
            family_key=state.snapshot.familyKey,
            family_name=state.snapshot.familyName,
            technology=state.snapshot.technology,
            document=document,
            exclude_proposal_id=proposal_id,
        )
        if len(snapshots) != 1:
            raise PayloadProducerError(
                "AI payload revision must return exactly one extraction"
            )
        return PayloadPreview(
            weakness_id=state.snapshot.weaknessId,
            source_ref=document.source_ref,
            snapshots=snapshots,
        )

    def write_revision(
        self,
        proposal_id: str,
    ) -> RevisePayloadEvent:
        preview = self.preview_revision(proposal_id)
        state = self.service.get(proposal_id)
        review = next(
            (
                event
                for event in reversed(state.events)
                if isinstance(event, RequestPayloadChangesEvent)
            ),
            None,
        )
        if review is None:
            raise PayloadProducerError(
                f"{proposal_id}: missing human review comment"
            )
        return self.service.revise(
            proposal_id,
            preview.snapshots[0],
            actor=self.settings.producer_name,
            actor_type="ai",
            response=review.comment,
        )