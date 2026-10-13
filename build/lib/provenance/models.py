from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ProvenanceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceSnapshot(ProvenanceModel):
    requestUrl: str = Field(min_length=1)
    resolvedUrl: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    byteLength: int = Field(ge=0)
    retrievedAt: datetime
    etag: str | None = None
    lastModified: str | None = None
    status: int = Field(ge=100, le=599)
    encoding: str = Field(default="utf-8", min_length=1)


class BuildManifest(ProvenanceModel):
    schemaVersion: Literal[1] = 1
    createdAt: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    sources: list[SourceSnapshot]
    stageSummaries: dict[str, Any] | None = None
    graphCounts: dict[str, Any] | None = None
    graphDigest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )

    @model_validator(mode="after")
    def request_urls_are_unique(self) -> Self:
        urls = [entry.requestUrl for entry in self.sources]
        if len(urls) != len(set(urls)):
            raise ValueError("source manifest has duplicate requestUrl values")
        return self

    @classmethod
    def read(cls, path: str | Path) -> "BuildManifest":
        source = Path(path)
        try:
            return cls.model_validate_json(
                source.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, ValueError) as exc:
            raise ValueError(
                f"{source}: invalid source manifest: {exc}"
            ) from exc

    def write(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            dir=destination.parent,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(
                    self.model_dump(mode="json", exclude_none=True),
                    handle,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, destination)
            temporary_name = ""
        finally:
            if temporary_name:
                Path(temporary_name).unlink(missing_ok=True)

    def validate_build_result(self, result: dict[str, Any]) -> None:
        """Prove replay produced the graph and stage summaries recorded live."""

        if (
            self.stageSummaries is None
            or self.graphCounts is None
            or self.graphDigest is None
        ):
            raise ValueError(
                "source manifest lacks stageSummaries, graphCounts, or "
                "graphDigest; "
                "it cannot prove exact replay"
            )
        if result.get("stages") != self.stageSummaries:
            raise ValueError(
                "replay stage summaries differ from source manifest"
            )
        if result.get("graph") != self.graphCounts:
            raise ValueError(
                "replay graph counts differ from source manifest"
            )
        if result.get("graphDigest") != self.graphDigest:
            raise ValueError(
                "replay graph digest differs from source manifest"
            )
