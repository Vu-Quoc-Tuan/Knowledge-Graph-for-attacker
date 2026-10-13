"""Parse GHSA GraphQL output into the shared structured vulnerability DTO."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ckg.ingestion.cve.models import (
    AffectedProduct,
    AffectedVersion,
    ReportedWeakness,
    StructuredVulnerabilityRecord,
)


def _timestamp(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def parse_ghsa_response(payload: dict[str, Any], *, source_url: str) -> StructuredVulnerabilityRecord:
    advisory = payload.get("data", {}).get("securityAdvisory")
    if not isinstance(advisory, dict) or not advisory.get("ghsaId"):
        raise ValueError("GitHub response has no securityAdvisory")
    identifiers = {
        str(item.get("value"))
        for item in advisory.get("identifiers", [])
        if isinstance(item, dict) and item.get("value")
    }
    aliases = tuple(sorted(identifier for identifier in identifiers if identifier != advisory["ghsaId"]))
    weaknesses = tuple(
        ReportedWeakness(cwe_id=str(node["cweId"]), json_pointer=f"/data/securityAdvisory/cwes/nodes/{index}/cweId")
        for index, node in enumerate(advisory.get("cwes", {}).get("nodes", []))
        if isinstance(node, dict) and str(node.get("cweId", "")).startswith("CWE-")
    )
    affected: list[AffectedProduct] = []
    for item in advisory.get("vulnerabilities", []):
        package = item.get("package", {}) if isinstance(item, dict) else {}
        versions: list[AffectedVersion] = []
        if item.get("vulnerableVersionRange"):
            versions.append(AffectedVersion(str(item["vulnerableVersionRange"]), "affected"))
        if isinstance(item.get("firstPatchedVersion"), dict) and item["firstPatchedVersion"].get("identifier"):
            versions.append(AffectedVersion(str(item["firstPatchedVersion"]["identifier"]), "fixed"))
        affected.append(
            AffectedProduct(
                vendor=None,
                product=str(package["name"]) if package.get("name") else None,
                package_name=str(package["name"]) if package.get("name") else None,
                ecosystem=str(package["ecosystem"]) if package.get("ecosystem") else None,
                versions=tuple(versions),
                source_pointer=f"/data/securityAdvisory/vulnerabilities/{len(affected)}",
                aliases=(str(package["name"]),) if package.get("name") else (),
            )
        )
    return StructuredVulnerabilityRecord(
        record_id=str(advisory["ghsaId"]),
        source_kind="ghsa",
        source_url=source_url,
        source_revision=advisory.get("updatedAt"),
        state="WITHDRAWN" if advisory.get("withdrawalsAt") else "PUBLISHED",
        published_at=_timestamp(advisory.get("publishedAt")),
        updated_at=_timestamp(advisory.get("updatedAt")),
        title=str(advisory["summary"]) if advisory.get("summary") else None,
        description=str(advisory["description"]) if advisory.get("description") else None,
        aliases=aliases,
        weaknesses=weaknesses,
        affected=tuple(affected),
        references=tuple(
            str(reference["url"])
            for reference in advisory.get("references", [])
            if isinstance(reference, dict) and reference.get("url")
        ),
    )
