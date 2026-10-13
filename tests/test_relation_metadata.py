from __future__ import annotations

from proposals.models import Evidence, ProposalSnapshot, RetrievalMetadata


def test_ai_snapshot_keeps_retrieval_audit_metadata() -> None:
    metadata = RetrievalMetadata(
        score=0.71,
        scoreType="cosine_similarity",
        candidateRank=1,
        candidateSetSize=5,
        embeddingModel="nvidia/nv-embedcode-7b-v1@provider",
        subjectTextHash="a" * 64,
        objectTextHash="b" * 64,
    )
    snapshot = ProposalSnapshot(
        subjectWeaknessId="LOCAL-1",
        predicate="SIMILAR_TO",
        objectWeaknessId="CWE-89",
        dimension="mechanism",
        rationale="Both cross an interpreter boundary.",
        evidence=[Evidence(sourceRef="source", excerpt="evidence")],
        producerKind="ai",
        producerName="mistral-large",
        producerVersion="v1",
        retrieval=metadata,
    )
    dumped = snapshot.model_dump(mode="json")
    assert dumped["retrieval"] == metadata.model_dump(mode="json")


def test_human_snapshot_may_omit_retrieval_metadata() -> None:
    snapshot = ProposalSnapshot(
        subjectWeaknessId="LOCAL-1",
        predicate="CHILD_OF",
        objectWeaknessId="CWE-74",
        rationale="Reviewed classification.",
        evidence=[Evidence(sourceRef="source", excerpt="evidence")],
        producerKind="human",
        producerName="reviewer",
    )
    assert snapshot.retrieval is None
