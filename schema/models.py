from typing import Any, Literal, Self
from pydantic import BaseModel, ConfigDict, Field, model_validator

from utils.identifiers import (
    PAYLOAD_EVENT_ID_PATTERN,
    PAYLOAD_FAMILY_KEY_PATTERN,
    PAYLOAD_PROPOSAL_ID_PATTERN,
    RELATION_EVENT_ID_PATTERN,
    RELATION_PROPOSAL_ID_PATTERN,
    WEAKNESS_ID_PATTERN,
)

class GraphModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    def to_props(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)

class Weakness(GraphModel):
    weaknessId: str = Field(pattern=WEAKNESS_ID_PATTERN)
    namespace: str = Field(pattern=r"^[A-Z][A-Z0-9]*$")
    externalId: str | None = None
    cweId: str | None = Field(default=None, pattern=r"^CWE-[0-9]+$")
    name: str = ""
    summary: str = ""
    lifecycleStatus: str = Field(
        default="accepted", pattern=r"^(proposed|accepted|deprecated)$"
    )
    supersededBy: str | None = Field(default=None, pattern=WEAKNESS_ID_PATTERN)
    origin: str = "MITRE"
    sourceType: str = "authoritative"
    sourceUrl: str | None = None
    sourceTitle: str | None = None
    sourceExcerpt: str | None = None
    sourceHash: str | None = None
    sourceSnapshot: str | None = None
    declaredBy: str | None = None
    createdAt: str | None = None
    updatedAt: str | None = None
    abstraction: str | None = None
    top25Year: int | None = None
    top25Rank: int | None = Field(default=None, ge=1, le=25)
    top25Score: float | None = Field(default=None, ge=0)
    kevCount: int | None = Field(default=None, ge=0)
    top25Source: str | None = None
    trackingSource: str | None = None
    trackingReason: str | None = None
    #: True when the weakness has at least one WSTG test mapping.
    webTestable: bool | None = None
    #: Detection-relevant content lifted from the MITRE CWE record.
    likelihoodOfExploit: str | None = None
    detectionMethods: list[str] | None = None
    mitigations: list[str] | None = None
    demonstrativeExamples: list[str] | None = None
    applicablePlatforms: list[str] | None = None

    @model_validator(mode="after")
    def identity_matches_namespace(self) -> Self:
        prefix = self.weaknessId.split("-", 1)[0]
        if prefix != self.namespace:
            raise ValueError("namespace must match weaknessId prefix")
        if self.cweId is not None and self.cweId != self.weaknessId:
            raise ValueError("cweId must match weaknessId")
        return self

class RelationProposal(GraphModel):
    proposalId: str = Field(pattern=RELATION_PROPOSAL_ID_PATTERN)
    status: Literal[
        "pending",
        "changes_requested",
        "accepted",
        "rejected",
        "retracted",
    ]
    revision: int = Field(ge=1)
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    subjectWeaknessId: str = Field(pattern=WEAKNESS_ID_PATTERN)
    predicate: Literal["CHILD_OF", "SIMILAR_TO"]
    objectWeaknessId: str = Field(pattern=WEAKNESS_ID_PATTERN)
    dimension: str | None = None
    rationale: str = Field(min_length=1)
    evidenceSourceRefs: list[str] = Field(min_length=1)
    evidenceExcerpts: list[str] = Field(min_length=1)
    producerKind: Literal["human", "ai", "rule"]
    producerName: str = Field(min_length=1)
    producerVersion: str | None = None
    retrievalScore: float | None = Field(default=None, ge=-1, le=1)
    retrievalScoreType: Literal["cosine_similarity"] | None = None
    candidateRank: int | None = Field(default=None, ge=1)
    candidateSetSize: int | None = Field(default=None, ge=1)
    embeddingModel: str | None = None
    subjectTextHash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    objectTextHash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    createdAt: str = Field(min_length=1)
    updatedAt: str = Field(min_length=1)
    acceptedBy: str | None = None
    acceptedAt: str | None = None
    retractedBy: str | None = None
    retractedAt: str | None = None
    retractionReason: str | None = None

    @model_validator(mode="after")
    def evidence_arrays_are_aligned(self) -> Self:
        if len(self.evidenceSourceRefs) != len(
            self.evidenceExcerpts
        ):
            raise ValueError(
                "proposal evidence arrays must have equal length"
            )
        return self


class RelationEventNode(GraphModel):
    eventId: str = Field(pattern=RELATION_EVENT_ID_PATTERN)
    proposalId: str = Field(pattern=RELATION_PROPOSAL_ID_PATTERN)
    schemaVersion: Literal[1]
    eventType: Literal[
        "propose",
        "request_changes",
        "revise",
        "approve",
        "reject",
        "retract",
    ]
    occurredAt: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    actorType: Literal["human", "ai", "rule"]
    comment: str | None = None
    response: str | None = None
    reason: str | None = None
    subjectWeaknessId: str | None = Field(
        default=None,
        pattern=WEAKNESS_ID_PATTERN,
    )
    predicate: Literal["CHILD_OF", "SIMILAR_TO"] | None = None
    objectWeaknessId: str | None = Field(
        default=None,
        pattern=WEAKNESS_ID_PATTERN,
    )
    dimension: str | None = None
    rationale: str | None = None
    producerKind: Literal["human", "ai", "rule"] | None = None
    producerName: str | None = None
    producerVersion: str | None = None
    retrievalScore: float | None = Field(default=None, ge=-1, le=1)
    retrievalScoreType: Literal["cosine_similarity"] | None = None
    candidateRank: int | None = Field(default=None, ge=1)
    candidateSetSize: int | None = Field(default=None, ge=1)
    embeddingModel: str | None = None
    subjectTextHash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    objectTextHash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    evidenceSourceRefs: list[str] | None = None
    evidenceExcerpts: list[str] | None = None

    @model_validator(mode="after")
    def snapshot_properties_are_coherent(self) -> Self:
        evidence_lengths = (
            len(self.evidenceSourceRefs)
            if self.evidenceSourceRefs is not None
            else None,
            len(self.evidenceExcerpts)
            if self.evidenceExcerpts is not None
            else None,
        )
        if evidence_lengths[0] != evidence_lengths[1]:
            raise ValueError(
                "event evidence arrays must both be absent "
                "or have equal length"
            )
        if self.eventType in {"propose", "revise"}:
            required = (
                self.subjectWeaknessId,
                self.predicate,
                self.objectWeaknessId,
                self.rationale,
                self.producerKind,
                self.producerName,
                self.evidenceSourceRefs,
            )
            if any(value is None for value in required):
                raise ValueError(
                    "proposal snapshot fields are required on "
                    "propose and revise events"
                )
        return self


class PayloadProposal(GraphModel):
    proposalId: str = Field(pattern=PAYLOAD_PROPOSAL_ID_PATTERN)
    status: Literal[
        "pending",
        "changes_requested",
        "tested",
        "accepted",
        "rejected",
    ]
    revision: int = Field(ge=1)
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    weaknessId: str = Field(pattern=WEAKNESS_ID_PATTERN)
    payloadValue: str = Field(min_length=1)
    familyKey: str = Field(pattern=PAYLOAD_FAMILY_KEY_PATTERN)
    familyName: str = Field(min_length=1)
    technology: str | None = None
    rationale: str = Field(min_length=1)
    sourceRef: str = Field(min_length=1)
    sourceExcerpt: str = Field(min_length=1)
    producerKind: Literal["human", "ai", "rule"]
    producerName: str = Field(min_length=1)
    producerVersion: str | None = None
    createdAt: str = Field(min_length=1)
    updatedAt: str = Field(min_length=1)
    latestValidationResult: Literal[
        "passed", "failed", "inconclusive"
    ] | None = None
    testedBy: str | None = None
    testedAt: str | None = None
    acceptedBy: str | None = None
    acceptedAt: str | None = None


class PayloadEventNode(GraphModel):
    eventId: str = Field(pattern=PAYLOAD_EVENT_ID_PATTERN)
    proposalId: str = Field(pattern=PAYLOAD_PROPOSAL_ID_PATTERN)
    schemaVersion: Literal[1]
    eventType: Literal[
        "propose",
        "request_changes",
        "revise",
        "record_validation",
        "approve",
        "reject",
    ]
    occurredAt: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    actorType: Literal["human", "ai", "rule"]
    comment: str | None = None
    response: str | None = None
    weaknessId: str | None = Field(
        default=None,
        pattern=WEAKNESS_ID_PATTERN,
    )
    payloadValue: str | None = None
    familyKey: str | None = None
    familyName: str | None = None
    technology: str | None = None
    rationale: str | None = None
    sourceRef: str | None = None
    sourceExcerpt: str | None = None
    producerKind: Literal["human", "ai", "rule"] | None = None
    producerName: str | None = None
    producerVersion: str | None = None
    validationRevision: int | None = None
    validationResult: Literal[
        "passed", "failed", "inconclusive"
    ] | None = None
    validationEnvironment: str | None = None
    validationTargetRef: str | None = None
    validationTargetHash: str | None = None
    validationExecutionRef: str | None = None
    validationExecutionHash: str | None = None
    validationObservedOutcome: str | None = None
    validationEvidenceRef: str | None = None
    validationEvidenceHash: str | None = None


class CRE(GraphModel):
    creId: str
    name: str = ""
    source: str = "opencre"


class TestActivity(GraphModel):
    wstgId: str = Field(pattern=r"^WSTG-[A-Z]+-[0-9]+(?:\.[0-9]+)?$")
    #: None, not "": a TestActivity has two writers (OpenCRE names the id, the
    #: checklist and the WSTG pages carry the content) and `to_props` drops only
    #: None. Defaulting to "" made "I have no name" an actual property write, so
    #: the writer with nothing to say blanked the one that had content.
    name: str | None = None
    summary: str | None = None
    #: The WSTG checklist's per-test objectives, kept as a list so a consumer
    #: gets discrete testing goals rather than one blob.
    objectives: list[str] | None = None
    source: str | None = None
    url: str | None = None
    sourcePage: str | None = None


class MethodologyPage(GraphModel):
    """An official WSTG child page that has no standalone WSTG test ID."""

    sourcePage: str = Field(min_length=1)
    name: str | None = None
    summary: str | None = None
    source: str = "OWASP WSTG"
    url: str | None = None


def is_bare_activity(node: dict[str, Any]) -> bool:
    """True when a TestActivity is only a pointer, with no methodology behind it.

    OpenCRE names a WSTG id but carries no page content, and it names ids that
    WSTG's own checklist does not list (WSTG-INPV-00, a chapter rather than a
    test), which therefore stay content-free. One definition, used both to
    decide what to enrich and what to keep off a retrieval card, so the write
    and read sides cannot disagree about what counts as empty.

    Name as well as url: a node holding one without the other is still no use to
    a consumer, and checking both lets a graph an earlier bug left half-filled
    repair itself on the next run instead of staying silently blank.
    """
    return not node.get("url") or not node.get("name")


class Technology(GraphModel):
    name: str = Field(min_length=1)


FAMILY_KEY_PATTERN = PAYLOAD_FAMILY_KEY_PATTERN


class PayloadFamily(GraphModel):
    key: str = Field(pattern=FAMILY_KEY_PATTERN)
    name: str
    detectionSignal: str | None = None
    source: str = "PayloadsAllTheThings"


class Payload(GraphModel):
    payloadId: str = Field(pattern=r"^PAY-[0-9a-f]{16}$")
    value: str = Field(min_length=1)
    source: str = "PayloadsAllTheThings"
    origin: str = Field(
        default="patt",
        pattern=r"^(patt|local_manual|ai_extracted|rule_extracted)$",
    )
    curationStatus: str = Field(
        default="upstream_curated",
        pattern=r"^(upstream_curated|human_reviewed|machine_extracted)$",
    )
    validationStatus: str = Field(
        default="untested",
        pattern=r"^(untested|tested)$",
    )
    sourceFile: str | None = None
    sourceUrl: str | None = None
    section: str | None = None
    #: How the payload was lifted out of the markdown:
    #: "code_block" or "table_cell"
    extraction: str | None = None


class DetectionSignal(GraphModel):
    key: str = Field(pattern=r"^[a-z][a-z0-9_]+$")
    name: str
    trustLevel: str = Field(
        default="strategy_hint", pattern=r"^(strategy_hint|accepted)$"
    )
    observableKind: str | None = Field(
        default=None,
        pattern=r"^(response|timing|out_of_band|state|execution)$",
    )
    observation: str | None = None
    successCriteria: str | None = None
    baselineRequired: bool | None = None
    threshold: str | None = None
    correlationRequirement: str | None = None
    applicabilityNotes: str | None = None
    weaknessId: str | None = Field(default=None, pattern=WEAKNESS_ID_PATTERN)
    familyKey: str | None = Field(default=None, pattern=FAMILY_KEY_PATTERN)
    technology: str | None = None
    sourceRef: str | None = None
    sourceHash: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    reviewedBy: str | None = None
    reviewedAt: str | None = None


class Scenario(GraphModel):
    # SCN-<weaknessId>-[<technology>-]<familyKey>.
    scenarioId: str = Field(
        pattern=(
            r"^SCN-[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+-"
            r"(?:.+-)?[a-z][a-z0-9]*\.[a-z_]+$"
        )
    )
    generated: bool = True
    testReady: bool = False
    confidence: float | None = Field(default=None, ge=0, le=1)
    methodologyStatus: str = Field(
        default="missing", pattern=r"^(direct|descendant|missing)$"
    )
    detectionSignalStatus: str = Field(
        default="missing", pattern=r"^(strategy_hint|accepted|missing)$"
    )

    @model_validator(mode="after")
    def test_readiness_requires_a_detection_contract(self) -> Self:
        if self.testReady and self.detectionSignalStatus == "missing":
            raise ValueError(
                "testReady scenario requires strategy_hint or accepted signal"
            )
        return self


class Vulnerability(GraphModel):
    vulnId: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    title: str = ""
    description: str = ""
    publishedAt: str | None = None
    observedAt: str | None = None
    epistemicStatus: Literal[
        "observed", "inferred", "validated", "canonical"
    ] = "observed"
    cweId: str | None = None
    inputVector: str | None = None
    inputParameter: str | None = None
    mechanism: str | None = None
    impact: str | None = None
    precondition: str | None = None


class Evidence(GraphModel):
    evidenceId: str = Field(pattern=r"^EVD-[0-9a-f]{8,64}$")
    kind: Literal[
        "advisory", "commit_patch", "poc_script", "writeup"
    ] = "advisory"
    sourceRef: str = Field(min_length=1)
    sourceHash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    excerpt: str = Field(min_length=1)
    observedAt: str | None = None


class Product(GraphModel):
    name: str = Field(min_length=1)
    vendor: str | None = None


class Component(GraphModel):
    componentId: str = Field(min_length=1)
    name: str = Field(min_length=1)
    path: str | None = None


class VersionRange(GraphModel):
    rangeId: str = Field(min_length=1)
    spec: str = Field(min_length=1)
    status: Literal["affected", "fixed"] = "affected"


class ScenarioFragment(GraphModel):
    fragmentId: str = Field(pattern=r"^FRAG-[A-Za-z0-9_-]+$")
    kind: Literal["setup", "input_mutation", "trigger", "oracle", "cleanup"]
    name: str = Field(min_length=1)
    description: str = ""
    requirements: list[str] = Field(default_factory=list)
    actionTemplate: str = Field(min_length=1)


class DetectionHypothesis(GraphModel):
    hypothesisId: str = Field(pattern=r"^HYP-[A-Za-z0-9_.-]+$")
    targetVulnId: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    sourceChannel: str = Field(min_length=1)
    mutationStrategy: str = Field(min_length=1)
    triggerPattern: str = Field(min_length=1)
    oracleFamily: str = Field(min_length=1)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    rationale: str = ""
    basedOnVulnId: str | None = None
    basedOnWeaknessId: str | None = None
    status: Literal["proposed", "accepted", "disproved"] = "proposed"


NODE_KEYS: dict[str, str] = {
    "Weakness": "weaknessId",
    "Vulnerability": "vulnId",
    "Evidence": "evidenceId",
    "Product": "name",
    "Component": "componentId",
    "VersionRange": "rangeId",
    "ScenarioFragment": "fragmentId",
    "DetectionHypothesis": "hypothesisId",
    "RelationProposal": "proposalId",
    "RelationEvent": "eventId",
    "PayloadProposal": "proposalId",
    "PayloadEvent": "eventId",
    "CRE": "creId",
    "TestActivity": "wstgId",
    "MethodologyPage": "sourcePage",
    "Technology": "name",
    "PayloadFamily": "key",
    "Payload": "payloadId",
    "DetectionSignal": "key",
    "Scenario": "scenarioId",
    "ValidationRecord": "validationId",
}
