from pydantic import Field

from ckg.domain.value_objects.base import DomainModel


class Technique(DomainModel):
    technique_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    parent_id: str | None = None
    aliases: tuple[str, ...] = ()
