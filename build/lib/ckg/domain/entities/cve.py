from datetime import datetime

from pydantic import Field

from ckg.domain.value_objects.base import DomainModel
from ckg.domain.value_objects.version_range import VersionRange


class Vulnerability(DomainModel):
    vulnerability_id: str = Field(pattern=r"^(CVE-[0-9]{4}-[0-9]+|GHSA-[A-Za-z0-9-]+)$")
    title: str = Field(min_length=1)
    published_at: datetime
    description: str | None = None
    aliases: tuple[str, ...] = ()
    version_ranges: tuple[VersionRange, ...] = ()
