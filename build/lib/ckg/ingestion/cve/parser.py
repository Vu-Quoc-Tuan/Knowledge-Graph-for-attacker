"""Parse NVD API 2.0 and CVE JSON 5 records into a shared multi-label DTO."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

from ckg.ingestion.cve.models import (
    AffectedProduct,
    AffectedVersion,
    ReportedWeakness,
    StructuredVulnerabilityRecord,
)


def _timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # NVD API values are UTC timestamps but some fixtures/exports omit `Z`.
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _english_text(entries: object, *, field: str = "value") -> str | None:
    if not isinstance(entries, list):
        return None
    english = next(
        (item for item in entries if isinstance(item, dict) and str(item.get("lang", "")).lower().startswith("en")),
        None,
    )
    candidate = english or next((item for item in entries if isinstance(item, dict)), None)
    value = candidate.get(field) if candidate else None
    return str(value) if value else None


def _cwe_identifier(value: object) -> str | None:
    candidate = str(value or "").strip().upper()
    return candidate if candidate.startswith("CWE-") and candidate[4:].isdigit() else None


def _split_cpe23(criteria: str) -> tuple[str, ...]:
    """Split a CPE 2.3 URI while respecting escaped separators."""
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for character in criteria:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    parts.append("".join(current))
    return tuple(parts)


def _cpe_component(value: object) -> str | None:
    candidate = unquote(str(value or "")).strip()
    if not candidate or candidate in {"*", "-"}:
        return None
    return candidate


def _cpe_version_expression(match: dict[str, Any], version: str | None) -> str | None:
    lower_including = _cpe_component(match.get("versionStartIncluding"))
    lower_excluding = _cpe_component(match.get("versionStartExcluding"))
    upper_including = _cpe_component(match.get("versionEndIncluding"))
    upper_excluding = _cpe_component(match.get("versionEndExcluding"))
    if not any((lower_including, lower_excluding, upper_including, upper_excluding)):
        return version
    expressions: list[str] = []
    if lower_including:
        expressions.append(f">= {lower_including}")
    elif lower_excluding:
        expressions.append(f"> {lower_excluding}")
    if upper_including:
        expressions.append(f"<= {upper_including}")
    elif upper_excluding:
        expressions.append(f"< {upper_excluding}")
    return ", ".join(expressions) or version


def _iter_nvd_cpe_matches(node: object, pointer: str):
    if not isinstance(node, dict):
        return
    for index, match in enumerate(node.get("cpeMatch", [])):
        if isinstance(match, dict):
            yield match, f"{pointer}/cpeMatch/{index}"
    for index, child in enumerate(node.get("children", [])):
        yield from _iter_nvd_cpe_matches(child, f"{pointer}/children/{index}")


def _parse_nvd_affected(cve: dict[str, Any], *, outer_index: int) -> tuple[AffectedProduct, ...]:
    affected: list[AffectedProduct] = []
    seen: set[tuple[object, ...]] = set()
    for configuration_index, configuration in enumerate(cve.get("configurations", [])):
        pointer = f"/vulnerabilities/{outer_index}/cve/configurations/{configuration_index}/nodes/0"
        for node_index, node in enumerate(configuration.get("nodes", [])):
            node_pointer = f"/vulnerabilities/{outer_index}/cve/configurations/{configuration_index}/nodes/{node_index}"
            for match, match_pointer in _iter_nvd_cpe_matches(node, node_pointer):
                if match.get("vulnerable") is False:
                    continue
                criteria = str(match.get("criteria") or match.get("cpe23Uri") or "")
                parts = _split_cpe23(criteria) if criteria else ()
                if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
                    continue
                vendor = _cpe_component(parts[3])
                product = _cpe_component(parts[4])
                version = _cpe_component(parts[5])
                if not product:
                    continue
                expression = _cpe_version_expression(match, version)
                versions = (AffectedVersion(expression=expression, status="affected"),) if expression else ()
                identity = (vendor, product, "cpe", tuple((item.expression, item.status) for item in versions))
                if identity in seen:
                    continue
                seen.add(identity)
                affected.append(
                    AffectedProduct(
                        vendor=vendor,
                        product=product,
                        package_name=None,
                        ecosystem="cpe",
                        versions=versions,
                        source_pointer=match_pointer + "/criteria",
                        cpe_uri=criteria or None,
                        aliases=tuple(
                            alias
                            for alias in (f"{vendor}/{product}" if vendor else None, product)
                            if alias
                        ),
                    )
                )
    return tuple(affected)


def parse_nvd_response(payload: dict[str, Any], *, source_url: str) -> tuple[StructuredVulnerabilityRecord, ...]:
    """Parse NVD CVE API 2.0 response; it may contain one or many records."""
    records: list[StructuredVulnerabilityRecord] = []
    for outer_index, outer in enumerate(payload.get("vulnerabilities", [])):
        cve = outer.get("cve", {}) if isinstance(outer, dict) else {}
        identifier = str(cve.get("id", ""))
        if not identifier.startswith("CVE-"):
            continue
        weaknesses: list[ReportedWeakness] = []
        for weakness_index, weakness in enumerate(cve.get("weaknesses", [])):
            for description_index, description in enumerate(weakness.get("description", [])):
                cwe_id = _cwe_identifier(description.get("value"))
                if cwe_id:
                    weaknesses.append(ReportedWeakness(cwe_id, f"/vulnerabilities/{outer_index}/cve/weaknesses/{weakness_index}/description/{description_index}/value"))
        references = tuple(
            str(reference["url"])
            for reference in cve.get("references", [])
            if isinstance(reference, dict) and reference.get("url")
        )
        affected = _parse_nvd_affected(cve, outer_index=outer_index)
        records.append(
            StructuredVulnerabilityRecord(
                record_id=identifier,
                source_kind="nvd",
                source_url=source_url,
                source_revision=str(cve.get("lastModified") or "") or None,
                state=str(cve.get("vulnStatus") or "UNKNOWN").upper(),
                published_at=_timestamp(cve.get("published")),
                updated_at=_timestamp(cve.get("lastModified")),
                title=None,
                description=_english_text(cve.get("descriptions")),
                aliases=(),
                weaknesses=tuple(sorted(set(weaknesses), key=lambda item: (item.cwe_id, item.json_pointer))),
                affected=affected,
                references=references,
            )
        )
    return tuple(records)


def _version_expression(version: dict[str, Any]) -> str | None:
    base = str(version.get("version") or "").strip()
    if not base:
        return None
    less_than = str(version.get("lessThan") or version.get("lessThanOrEqual") or "").strip()
    if not less_than:
        return base
    operator = "<=" if version.get("lessThanOrEqual") else "<"
    return f">= {base}, {operator} {less_than}"


def _parse_cve_container(container: dict[str, Any], pointer: str) -> tuple[tuple[ReportedWeakness, ...], tuple[AffectedProduct, ...], tuple[str, ...], str | None, str | None]:
    weaknesses: list[ReportedWeakness] = []
    for type_index, problem_type in enumerate(container.get("problemTypes", [])):
        for description_index, description in enumerate(problem_type.get("descriptions", [])):
            cwe_id = _cwe_identifier(description.get("cweId"))
            if cwe_id:
                weaknesses.append(ReportedWeakness(cwe_id, f"{pointer}/problemTypes/{type_index}/descriptions/{description_index}/cweId"))
    affected: list[AffectedProduct] = []
    for affected_index, item in enumerate(container.get("affected", [])):
        if not isinstance(item, dict):
            continue
        versions = tuple(
            AffectedVersion(expression=expression, status=str(version.get("status", "unknown")).lower())
            for version in item.get("versions", [])
            if isinstance(version, dict) and (expression := _version_expression(version))
        )
        affected.append(
            AffectedProduct(
                vendor=str(item["vendor"]) if item.get("vendor") else None,
                product=str(item["product"]) if item.get("product") else None,
                package_name=str(item["packageName"]) if item.get("packageName") else None,
                ecosystem=str(item["collectionURL"]) if item.get("collectionURL") else None,
                versions=versions,
                source_pointer=f"{pointer}/affected/{affected_index}",
                aliases=tuple(
                    alias
                    for alias in (
                        f"{item['vendor']}/{item['product']}"
                        if item.get("vendor") and item.get("product")
                        else None,
                        str(item["product"]) if item.get("product") else None,
                    )
                    if alias
                ),
            )
        )
    references = tuple(
        str(reference["url"])
        for reference in container.get("references", [])
        if isinstance(reference, dict) and reference.get("url")
    )
    return (
        tuple(weaknesses),
        tuple(affected),
        references,
        str(container.get("title")) if container.get("title") else None,
        _english_text(container.get("descriptions")),
    )


def parse_cve_services_record(payload: dict[str, Any], *, source_url: str) -> StructuredVulnerabilityRecord:
    """Parse CVE JSON 5 CNA plus ADP containers without flattening their source identity."""
    metadata = payload.get("cveMetadata", {})
    identifier = str(metadata.get("cveId", ""))
    if not identifier.startswith("CVE-"):
        raise ValueError("CVE Services record lacks a CVE identifier")
    containers = payload.get("containers", {})
    source_containers: list[tuple[str, dict[str, Any]]] = []
    if isinstance(containers.get("cna"), dict):
        source_containers.append(("/containers/cna", containers["cna"]))
    for index, container in enumerate(containers.get("adp", [])):
        if isinstance(container, dict):
            source_containers.append((f"/containers/adp/{index}", container))
    weaknesses: list[ReportedWeakness] = []
    affected: list[AffectedProduct] = []
    references: list[str] = []
    title: str | None = None
    description: str | None = None
    for pointer, container in source_containers:
        current_weaknesses, current_affected, current_references, current_title, current_description = _parse_cve_container(container, pointer)
        weaknesses.extend(current_weaknesses)
        affected.extend(current_affected)
        references.extend(current_references)
        title = title or current_title
        description = description or current_description
    return StructuredVulnerabilityRecord(
        record_id=identifier,
        source_kind="cve_services",
        source_url=source_url,
        source_revision=str(metadata.get("serial")) if metadata.get("serial") is not None else None,
        state=str(metadata.get("state") or "UNKNOWN").upper(),
        published_at=_timestamp(metadata.get("datePublished")),
        updated_at=_timestamp(metadata.get("dateUpdated")),
        title=title,
        description=description,
        aliases=(),
        weaknesses=tuple(sorted(set(weaknesses), key=lambda item: (item.cwe_id, item.json_pointer))),
        affected=tuple(affected),
        references=tuple(sorted(set(references))),
    )
