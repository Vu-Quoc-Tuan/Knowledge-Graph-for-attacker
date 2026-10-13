from pydantic import Field

from ckg.domain.value_objects.base import DomainModel


class EvidenceSpan(DomainModel):
    """A precise reference from a normalized claim back to immutable source bytes."""

    evidence_id: str = Field(pattern=r"^EVID-[A-Za-z0-9_.:-]+$")
    content_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    locator: str = Field(min_length=1)
    excerpt: str | None = None
