from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from pydantic import ValidationError

from ai_producers.evidence import (
    EvidenceCatalogError,
    relation_evidence_catalog,
    select_relation_evidence,
)
from ai_producers.models import (
    RelationAIResponse,
    compact_validation_error,
    relation_response_schema,
)
from ai_producers.prompts import (
    relation_create_messages,
    relation_revision_messages,
)
from ai_producers.provider import AISettings, StructuredChatProvider
from ai_producers.retriever import CandidateWeakness, EmbeddingRetriever
from ai_producers.embedding_cache import text_sha256
from ai_producers.retriever import canonical_weakness_text
from db.sink import GraphSink
from proposals.log import canonical_endpoints, proposal_fingerprint
from proposals.models import (
    ProposalSnapshot,
    ProposeEvent,
    RetrievalMetadata,
    RequestChangesEvent,
    ReviseEvent,
)
from proposals.service import RelationEventService


class RelationProducerError(ValueError):
    """Raised when AI relation output cannot become a safe proposal."""



@dataclass(frozen=True)
class RelationPreview:
    weakness_id: str
    snapshots: tuple[ProposalSnapshot, ...]
    retrieval_scores: tuple[tuple[str, float], ...]



class RelationAIProducer:
    def __init__(
        self,
        sink: GraphSink,
        retriever: EmbeddingRetriever,
        provider: StructuredChatProvider,
        service: RelationEventService,
        settings: AISettings,
    ) -> None:
        self.sink = sink
        self.retriever = retriever
        self.provider = provider
        self.service = service
        self.settings = settings

    def _context(
        self,
        weakness_id: str,
        top_k: int | None,
    ) -> tuple[
        dict[str, object],
        list[CandidateWeakness],
        dict[str, object],
        dict[str, object],
    ]:
        subject = self.sink.get_node(
            "Weakness",
            "weaknessId",
            weakness_id,
        )
        if subject is None:
            raise RelationProducerError(
                f"unknown Weakness: {weakness_id}"
            )
        candidates = self.retriever.candidates(
            self.sink,
            weakness_id,
            top_k,
        )
        if not candidates:
            raise RelationProducerError(
                f"{weakness_id}: no eligible embedding candidates"
            )
        catalog = relation_evidence_catalog(subject, candidates)
        prompt_catalog = {
            key: entry.prompt_value()
            for key, entry in catalog.items()
        }
        policy = self.service.policy.model_dump(mode="json")
        return subject, candidates, prompt_catalog, policy

    def _snapshots(
        self,
        weakness_id: str,
        candidates: Sequence[CandidateWeakness],
        raw_response: Mapping[str, object],
        *,
        exclude_proposal_id: str | None = None,
    ) -> tuple[ProposalSnapshot, ...]:
        try:
            response = RelationAIResponse.model_validate(
                raw_response,
                context={
                    "max_items": self.settings.max_relation_proposals
                },
            )
        except ValidationError as exc:
            raise RelationProducerError(
                "invalid AI relation response: "
                f"{compact_validation_error(exc)}"
            ) from exc
        subject = self.sink.get_node(
            "Weakness",
            "weaknessId",
            weakness_id,
        )
        if subject is None:
            raise RelationProducerError(
                f"unknown Weakness: {weakness_id}"
            )
        candidate_by_id = {
            candidate.weakness_id: candidate
            for candidate in candidates
        }
        candidate_rank = {
            candidate.weakness_id: rank
            for rank, candidate in enumerate(candidates, start=1)
        }
        subject_text_hash = text_sha256(
            canonical_weakness_text(subject)
        )
        catalog = relation_evidence_catalog(subject, candidates)
        snapshots: list[ProposalSnapshot] = []
        for item in response.proposals:
            if item.objectWeaknessId not in candidate_by_id:
                raise RelationProducerError(
                    f"AI selected object outside embedding shortlist: "
                    f"{item.objectWeaknessId}"
                )
            if item.objectWeaknessId == weakness_id:
                raise RelationProducerError(
                    f"AI proposed a self-relation: "
                    f"{weakness_id} {item.predicate} {weakness_id}"
                )
            predicate_policy = self.service.policy.predicates.get(
                item.predicate
            )
            if predicate_policy is None:
                raise RelationProducerError(
                    f"predicate is not enabled: {item.predicate}"
                )
            if predicate_policy.dimension_required:
                if item.dimension not in predicate_policy.allowed_dimensions:
                    raise RelationProducerError(
                        f"dimension {item.dimension!r} is not allowed "
                        f"for {item.predicate}"
                    )
            elif item.dimension is not None:
                raise RelationProducerError(
                    f"{item.predicate} does not allow dimensions"
                )
            try:
                evidence = select_relation_evidence(
                    catalog,
                    item.evidenceKeys,
                    subject_id=weakness_id,
                    object_id=item.objectWeaknessId,
                )
            except EvidenceCatalogError as exc:
                raise RelationProducerError(str(exc)) from exc
            snapshots.append(
                ProposalSnapshot(
                    subjectWeaknessId=weakness_id,
                    predicate=item.predicate,
                    objectWeaknessId=item.objectWeaknessId,
                    dimension=item.dimension,
                    rationale=item.rationale,
                    evidence=evidence,
                    producerKind="ai",
                    producerName=self.settings.producer_name,
                    producerVersion=self.settings.relation_producer_version,
                    retrieval=RetrievalMetadata(
                        score=candidate_by_id[item.objectWeaknessId].score,
                        scoreType="cosine_similarity",
                        candidateRank=candidate_rank[item.objectWeaknessId],
                        candidateSetSize=len(candidates),
                        embeddingModel=(
                            f"{self.retriever.model_name}@"
                            f"{self.retriever.model_version}"
                        ),
                        subjectTextHash=subject_text_hash,
                        objectTextHash=(
                            candidate_by_id[item.objectWeaknessId].text_hash
                        ),
                    ),
                )
            )
        self._preflight_fingerprints(
            snapshots,
            exclude_proposal_id=exclude_proposal_id,
        )
        return tuple(snapshots)

    def _preflight_fingerprints(
        self,
        snapshots: Sequence[ProposalSnapshot],
        *,
        exclude_proposal_id: str | None = None,
    ) -> None:
        for snapshot in snapshots:
            if self._graph_already_asserts(snapshot):
                raise RelationProducerError(
                    "graph already contains asserted relation "
                    f"{snapshot.subjectWeaknessId} "
                    f"{snapshot.predicate} "
                    f"{snapshot.objectWeaknessId}"
                )
        fingerprints = [
            proposal_fingerprint(snapshot, self.service.policy)
            for snapshot in snapshots
        ]
        if len(set(fingerprints)) != len(fingerprints):
            raise RelationProducerError(
                "AI response contains duplicate proposal fingerprints"
            )
        for state in self.service.list_proposals():
            if state.proposalId == exclude_proposal_id:
                continue
            if (
                state.fingerprint in fingerprints
                and state.status not in {"rejected", "retracted"}
            ):
                raise RelationProducerError(
                    "proposal fingerprint is already active or accepted "
                    f"as {state.proposalId}"
                )

    def _existing_claims(
        self,
        weakness_id: str,
        *,
        exclude_proposal_id: str | None = None,
    ) -> list[dict[str, object]]:
        return [
            {
                "proposalId": state.proposalId,
                "status": state.status,
                "subjectWeaknessId": state.snapshot.subjectWeaknessId,
                "predicate": state.snapshot.predicate,
                "objectWeaknessId": state.snapshot.objectWeaknessId,
                "dimension": state.snapshot.dimension,
            }
            for state in self.service.list_proposals()
            if state.status not in {"rejected", "retracted"}
            and state.proposalId != exclude_proposal_id
            and (
                state.snapshot.subjectWeaknessId == weakness_id
                or (
                    state.snapshot.predicate == "SIMILAR_TO"
                    and state.snapshot.objectWeaknessId == weakness_id
                )
            )
        ]

    def _graph_already_asserts(
        self,
        snapshot: ProposalSnapshot,
    ) -> bool:
        subject, object_id = canonical_endpoints(
            snapshot,
            self.service.policy,
        )
        for relation in self.sink.match_rels(
            snapshot.predicate,
            from_label="Weakness",
            to_label="Weakness",
        ):
            pair = (
                str(relation["from_value"]),
                str(relation["to_value"]),
            )
            if snapshot.predicate == "SIMILAR_TO":
                pair = tuple(sorted(pair))
            if pair != (subject, object_id):
                continue
            if snapshot.predicate == "CHILD_OF":
                return True
            dimensions = relation["props"].get("dimensions")
            if not isinstance(dimensions, list):
                return True
            if snapshot.dimension in dimensions:
                return True
        return False

    def preview(
        self,
        weakness_id: str,
        top_k: int | None = None,
    ) -> RelationPreview:
        subject, candidates, catalog, policy = self._context(
            weakness_id,
            top_k,
        )
        candidate_data = [
            {
                "weaknessId": candidate.weakness_id,
                "canonicalText": candidate.canonical_text,
                "score": candidate.score,
            }
            for candidate in candidates
        ]
        raw = self.provider.structured_chat(
            relation_create_messages(
                subject,
                candidate_data,
                catalog,
                policy,
                self._existing_claims(weakness_id),
            ),
            schema_name="relation_proposals",
            schema=relation_response_schema(
                [candidate.weakness_id for candidate in candidates],
                sorted(
                    {
                        dimension
                        for predicate in self.service.policy.predicates.values()
                        for dimension in predicate.allowed_dimensions
                    }
                ),
                self.settings.max_relation_proposals,
            ),
        )
        snapshots = self._snapshots(
            weakness_id,
            candidates,
            raw,
        )
        return RelationPreview(
            weakness_id=weakness_id,
            snapshots=snapshots,
            retrieval_scores=tuple(
                (candidate.weakness_id, candidate.score)
                for candidate in candidates
            ),
        )

    def write(
        self,
        weakness_id: str,
        top_k: int | None = None,
    ) -> list[ProposeEvent]:
        preview = self.preview(weakness_id, top_k)
        if not preview.snapshots:
            return []
        return self.service.create_many(
            preview.snapshots,
            actor=self.settings.producer_name,
            actor_type="ai",
        )

    def _revision_inputs(
        self,
        proposal_id: str,
        top_k: int | None,
    ):
        state = self.service.get(proposal_id)
        if state.status != "changes_requested":
            raise RelationProducerError(
                f"{proposal_id}: AI revision requires changes_requested"
            )
        if state.snapshot.producerKind != "ai":
            raise RelationProducerError(
                f"{proposal_id}: only AI proposals can be AI-revised"
            )
        review = next(
            (
                event
                for event in reversed(state.events)
                if isinstance(event, RequestChangesEvent)
            ),
            None,
        )
        if review is None:
            raise RelationProducerError(
                f"{proposal_id}: missing human review comment"
            )
        subject, candidates, catalog, policy = self._context(
            state.snapshot.subjectWeaknessId,
            top_k,
        )
        return state, review, subject, candidates, catalog, policy

    def preview_revision(
        self,
        proposal_id: str,
        top_k: int | None = None,
    ) -> RelationPreview:
        state, review, subject, candidates, catalog, policy = (
            self._revision_inputs(proposal_id, top_k)
        )
        candidate_data = [
            {
                "weaknessId": candidate.weakness_id,
                "canonicalText": candidate.canonical_text,
                "score": candidate.score,
            }
            for candidate in candidates
        ]
        raw = self.provider.structured_chat(
            relation_revision_messages(
                state.snapshot.model_dump(mode="json"),
                review.comment,
                subject,
                candidate_data,
                catalog,
                policy,
                self._existing_claims(
                    state.snapshot.subjectWeaknessId,
                    exclude_proposal_id=proposal_id
                ),
            ),
            schema_name="relation_revision",
            schema=relation_response_schema(
                [candidate.weakness_id for candidate in candidates],
                sorted(
                    {
                        dimension
                        for predicate in self.service.policy.predicates.values()
                        for dimension in predicate.allowed_dimensions
                    }
                ),
                1,
            ),
        )
        snapshots = self._snapshots(
            state.snapshot.subjectWeaknessId,
            candidates,
            raw,
            exclude_proposal_id=proposal_id,
        )
        if len(snapshots) != 1:
            raise RelationProducerError(
                "AI relation revision must return exactly one proposal"
            )
        self._preflight_fingerprints(
            snapshots,
            exclude_proposal_id=proposal_id,
        )
        return RelationPreview(
            weakness_id=state.snapshot.subjectWeaknessId,
            snapshots=snapshots,
            retrieval_scores=tuple(
                (candidate.weakness_id, candidate.score)
                for candidate in candidates
            ),
        )

    def write_revision(
        self,
        proposal_id: str,
        top_k: int | None = None,
    ) -> ReviseEvent:
        preview = self.preview_revision(proposal_id, top_k)
        state = self.service.get(proposal_id)
        review = next(
            (
                event
                for event in reversed(state.events)
                if isinstance(event, RequestChangesEvent)
            ),
            None,
        )
        if review is None:
            raise RelationProducerError(
                f"{proposal_id}: missing human review comment"
            )
        return self.service.revise(
            proposal_id,
            preview.snapshots[0],
            actor=self.settings.producer_name,
            actor_type="ai",
            response=review.comment,
        )
