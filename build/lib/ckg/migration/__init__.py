"""Adapters that move legacy graph data into the provenance-first v2 model."""

from ckg.migration.legacy_registry import (
    LegacyRegistryMigrationReport,
    migrate_legacy_vulnerability_registry,
)
from ckg.migration.legacy_vulnerability_events import (
    LegacyVulnerabilityEventMigrationReport,
    migrate_legacy_vulnerability_events,
)

__all__ = [
    "LegacyRegistryMigrationReport",
    "LegacyVulnerabilityEventMigrationReport",
    "migrate_legacy_vulnerability_events",
    "migrate_legacy_vulnerability_registry",
]
