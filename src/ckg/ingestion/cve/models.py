"""Source-neutral DTOs for structured vulnerability records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ReportedWeakness:
    cwe_id: str
    json_pointer: str


@dataclass(frozen=True)
class AffectedVersion:
    expression: str
    status: str


@dataclass(frozen=True)
class AffectedProduct:
    vendor: str | None
    product: str | None
    package_name: str | None
    ecosystem: str | None
    versions: tuple[AffectedVersion, ...] = ()
    source_pointer: str | None = None
    cpe_uri: str | None = None
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class StructuredVulnerabilityRecord:
    record_id: str
    source_kind: str
    source_url: str
    source_revision: str | None
    state: str
    published_at: datetime | None
    updated_at: datetime | None
    title: str | None
    description: str | None
    aliases: tuple[str, ...]
    weaknesses: tuple[ReportedWeakness, ...]
    affected: tuple[AffectedProduct, ...]
    references: tuple[str, ...]
