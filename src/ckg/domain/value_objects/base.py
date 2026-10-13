from pydantic import BaseModel, ConfigDict


class DomainModel(BaseModel):
    """Forbid silent schema drift in persisted scientific claims."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)
