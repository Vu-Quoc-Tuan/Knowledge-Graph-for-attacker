from datetime import datetime

from pydantic import Field

from ckg.domain.enums.relation_origin import RelationOrigin
from ckg.domain.value_objects.base import DomainModel


class Provenance(DomainModel):
    """Who supplied a claim and when that source became known to the system."""

    source_id: str = Field(min_length=1)
    source_kind: str = Field(min_length=1)
    retrieved_at: datetime
    source_url: str | None = None
    source_release: str | None = None
    origin: RelationOrigin = RelationOrigin.REPORTED_SOURCE
    extractor_name: str | None = None
    extractor_version: str | None = None
