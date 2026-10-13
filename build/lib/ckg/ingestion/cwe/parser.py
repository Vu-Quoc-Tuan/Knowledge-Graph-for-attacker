from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from xml.etree import ElementTree

from ckg.domain.entities.cwe import CanonicalCWEGroup, CanonicalCWERelation, CanonicalWeakness
from ckg.domain.enums.relation_origin import RelationOrigin
from ckg.domain.value_objects.provenance import Provenance
from ckg.ingestion.xml_utils import descendants, first_text, local_name


@dataclass(frozen=True)
class ParsedCWECatalog:
    source_release: str
    weaknesses: tuple[CanonicalWeakness, ...]
    relations: tuple[CanonicalCWERelation, ...]
    groups: tuple[CanonicalCWEGroup, ...]
    group_memberships: tuple[tuple[str, str, str | None], ...]


def _attribute(element: ElementTree.Element, *names: str) -> str | None:
    for name in names:
        value = element.attrib.get(name)
        if value:
            return value
    return None


def _relation_id(
    subject: str,
    predicate: str,
    object_: str,
    release: str,
    view: str | None,
    qualifier: str | None,
) -> str:
    material = "|".join((subject, predicate, object_, release, view or "", qualifier or ""))
    return f"CWE-REL-{hashlib.sha256(material.encode()).hexdigest()[:24]}"


def _mapping_reasons(element: ElementTree.Element) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                reason.attrib.get("Type", "").strip()
                for reason in descendants(element, "Reason")
                if reason.attrib.get("Type", "").strip()
            }
        )
    )


def _applicable_platforms(element: ElementTree.Element) -> tuple[str, ...]:
    """Keep each platform element and every canonical attribute deterministically."""
    values: list[str] = []
    for platforms in descendants(element, "Applicable_Platforms"):
        for platform in platforms:
            kind = local_name(platform)
            attributes = ";".join(
                f"{key}={value}" for key, value in sorted(platform.attrib.items())
            )
            text = " ".join(part.strip() for part in platform.itertext() if part.strip())
            values.append(f"{kind}:{attributes}" + (f";text={text}" if text else ""))
    return tuple(sorted(set(values)))


def parse_cwe_catalog(
    raw_xml: bytes,
    *,
    source_snapshot_digest: str,
    retrieved_at: datetime,
    source_url: str | None = None,
) -> ParsedCWECatalog:
    """Parse a pinned CWE XML release without dropping relation natures or views."""

    root = ElementTree.fromstring(raw_xml)
    release = root.attrib.get("Version")
    if not release:
        raise ValueError("CWE catalog has no Version")
    provenance = Provenance(
        source_id=f"MITRE-CWE-{release}",
        source_kind="mitre",
        source_url=source_url,
        source_release=release,
        retrieved_at=retrieved_at,
        origin=RelationOrigin.CANONICAL_SOURCE,
    )
    weaknesses: list[CanonicalWeakness] = []
    relations: list[CanonicalCWERelation] = []
    groups: list[CanonicalCWEGroup] = []
    memberships: list[tuple[str, str, str | None]] = []
    for element in descendants(root, "Weakness"):
        cwe_number = element.attrib.get("ID")
        name = element.attrib.get("Name")
        if not cwe_number or not name:
            raise ValueError("CWE Weakness requires ID and Name")
        subject = f"CWE-{cwe_number}"
        mapping_notes = next(descendants(element, "Mapping_Notes"), None)
        weaknesses.append(
            CanonicalWeakness(
                cwe_id=subject,
                name=name,
                source_release=release,
                source_snapshot_digest=source_snapshot_digest,
                retrieved_at=retrieved_at,
                abstraction=element.attrib.get("Abstraction"),
                description=first_text(element, "Description"),
                lifecycle_status=element.attrib.get("Status"),
                mapping_usage=first_text(mapping_notes, "Usage") if mapping_notes is not None else None,
                mapping_rationale=first_text(mapping_notes, "Rationale") if mapping_notes is not None else None,
                mapping_comments=first_text(mapping_notes, "Comments") if mapping_notes is not None else None,
                mapping_reasons=_mapping_reasons(mapping_notes) if mapping_notes is not None else (),
                applicable_platforms=_applicable_platforms(element),
            )
        )
        for related in descendants(element, "Related_Weakness"):
            object_number = _attribute(related, "CWE_ID", "CweID", "Cwe_ID")
            predicate = related.attrib.get("Nature")
            if not object_number or not predicate:
                continue
            object_ = f"CWE-{object_number}"
            view = _attribute(related, "View_ID", "ViewID", "View_Id")
            qualifier = related.attrib.get("Ordinal")
            relations.append(
                CanonicalCWERelation(
                    relation_id=_relation_id(subject, predicate, object_, release, view, qualifier),
                    subject_cwe_id=subject,
                    predicate=predicate,
                    object_cwe_id=object_,
                    source_release=release,
                    source_snapshot_digest=source_snapshot_digest,
                    view_id=view,
                    qualifier=qualifier,
                    provenance=provenance,
                )
            )
    for element_name, kind in (("Category", "CATEGORY"), ("View", "VIEW")):
        for element in descendants(root, element_name):
            number, name = element.attrib.get("ID"), element.attrib.get("Name")
            if not number or not name:
                continue
            group_id = f"CWE-{kind}-{number}"
            groups.append(CanonicalCWEGroup(group_id=group_id, kind=kind, name=name, source_release=release, source_snapshot_digest=source_snapshot_digest, retrieved_at=retrieved_at, lifecycle_status=element.attrib.get("Status"), description=first_text(element, "Summary")))
            for member in descendants(element, "Has_Member"):
                cwe_number = _attribute(member, "CWE_ID", "CweID")
                if cwe_number:
                    memberships.append((group_id, f"CWE-{cwe_number}", _attribute(member, "View_ID", "ViewID")))
    unique_groups = {group.group_id: group for group in groups}
    unique_memberships = set(memberships)
    return ParsedCWECatalog(
        source_release=release,
        weaknesses=tuple(sorted(weaknesses, key=lambda item: item.cwe_id)),
        relations=tuple(sorted(relations, key=lambda item: item.relation_id)),
        groups=tuple(sorted(unique_groups.values(), key=lambda item: item.group_id)),
        group_memberships=tuple(sorted(unique_memberships)),
    )
