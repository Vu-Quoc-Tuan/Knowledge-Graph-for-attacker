from datetime import datetime

from pydantic import Field

from ckg.domain.enums.fact_status import FactStatus
from ckg.domain.enums.relation_origin import RelationOrigin
from ckg.domain.value_objects.base import DomainModel
from ckg.domain.value_objects.provenance import Provenance


class CanonicalWeakness(DomainModel):
    cwe_id: str = Field(pattern=r"^CWE-[0-9]+$")
    name: str = Field(min_length=1)
    source_release: str = Field(min_length=1)
    source_snapshot_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    retrieved_at: datetime | None = None
    abstraction: str | None = None
    description: str | None = None
    lifecycle_status: str | None = None
    mapping_usage: str | None = None
    mapping_rationale: str | None = None
    mapping_comments: str | None = None
    mapping_reasons: tuple[str, ...] = ()
    applicable_platforms: tuple[str, ...] = ()
    status: FactStatus = FactStatus.CANONICAL


class CanonicalCWEGroup(DomainModel):
    group_id: str = Field(pattern=r"^CWE-(CATEGORY|VIEW)-[0-9]+$")
    kind: str = Field(pattern=r"^(CATEGORY|VIEW)$")
    name: str = Field(min_length=1)
    source_release: str = Field(min_length=1)
    source_snapshot_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    retrieved_at: datetime | None = None
    lifecycle_status: str | None = None
    description: str | None = None


class CanonicalCWERelation(DomainModel):
    relation_id: str = Field(min_length=1)
    subject_cwe_id: str = Field(pattern=r"^CWE-[0-9]+$")
    predicate: str = Field(min_length=1)
    object_cwe_id: str = Field(pattern=r"^CWE-[0-9]+$")
    source_release: str = Field(min_length=1)
    source_snapshot_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    view_id: str | None = None
    qualifier: str | None = None
    origin: RelationOrigin = RelationOrigin.CANONICAL_SOURCE
    provenance: Provenance
