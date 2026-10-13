from pydantic import Field

from ckg.domain.value_objects.base import DomainModel


class VersionRange(DomainModel):
    ecosystem: str = Field(min_length=1)
    expression: str = Field(min_length=1)
    status: str = Field(pattern=r"^(affected|fixed|unknown)$")
