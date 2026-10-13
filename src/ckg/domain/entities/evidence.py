from datetime import datetime

from pydantic import Field

from ckg.domain.value_objects.base import DomainModel


class Evidence(DomainModel):
    evidence_id: str = Field(pattern=r"^EVID-[A-Za-z0-9_.:-]+$")
    kind: str = Field(min_length=1)
    content_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    retrieved_at: datetime
    source_url: str | None = None
    storage_uri: str | None = None
