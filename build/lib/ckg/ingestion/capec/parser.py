from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from xml.etree import ElementTree

from ckg.domain.entities.capec import AttackPattern, AttackPrerequisite, AttackStep, CAPECWeaknessRelation
from ckg.domain.enums.relation_origin import RelationOrigin
from ckg.domain.value_objects.provenance import Provenance
from ckg.ingestion.xml_utils import descendants, first_text


@dataclass(frozen=True)
class ParsedCAPECCatalog:
    source_release: str
    patterns: tuple[AttackPattern, ...]
    related_weaknesses: tuple[CAPECWeaknessRelation, ...]
    steps: tuple[AttackStep, ...]
    prerequisites: tuple[AttackPrerequisite, ...]


def parse_capec_catalog(
    raw_xml: bytes,
    *,
    source_snapshot_digest: str,
    retrieved_at: datetime,
    source_url: str | None = None,
) -> ParsedCAPECCatalog:
    root = ElementTree.fromstring(raw_xml)
    release = root.attrib.get("Version")
    if not release:
        raise ValueError("CAPEC catalog has no Version")
    provenance = Provenance(
        source_id=f"MITRE-CAPEC-{release}",
        source_kind="mitre",
        source_url=source_url,
        source_release=release,
        retrieved_at=retrieved_at,
        origin=RelationOrigin.CANONICAL_SOURCE,
    )
    patterns: list[AttackPattern] = []
    relations: list[CAPECWeaknessRelation] = []
    steps: list[AttackStep] = []
    prerequisites: list[AttackPrerequisite] = []
    for element in descendants(root, "Attack_Pattern"):
        identifier = element.attrib.get("ID")
        name = element.attrib.get("Name")
        if not identifier or not name:
            raise ValueError("CAPEC Attack_Pattern requires ID and Name")
        capec_id = f"CAPEC-{identifier}"
        patterns.append(
            AttackPattern(
                capec_id=capec_id,
                name=name,
                source_release=release,
                source_snapshot_digest=source_snapshot_digest,
                retrieved_at=retrieved_at,
                description=first_text(element, "Description"),
            )
        )
        for ordinal, step in enumerate(descendants(element, "Attack_Step"), start=1):
            description = first_text(step, "Description")
            if description:
                steps.append(AttackStep(step_id=f"{capec_id}-STEP-{ordinal}", capec_id=capec_id, ordinal=ordinal, phase=first_text(step, "Phase"), description=description, retrieved_at=retrieved_at))
        for ordinal, prerequisite in enumerate(descendants(element, "Prerequisite"), start=1):
            description = " ".join(part.strip() for part in prerequisite.itertext() if part.strip())
            if description:
                prerequisites.append(AttackPrerequisite(prerequisite_id=f"{capec_id}-PREREQUISITE-{ordinal}", capec_id=capec_id, ordinal=ordinal, description=description, retrieved_at=retrieved_at))
        for related in descendants(element, "Related_Weakness"):
            cwe_number = related.attrib.get("CWE_ID")
            if not cwe_number:
                continue
            cwe_id = f"CWE-{cwe_number}"
            material = f"{capec_id}|{cwe_id}|{release}|{source_snapshot_digest}"
            relations.append(
                CAPECWeaknessRelation(
                    relation_id=f"CAPEC-REL-{hashlib.sha256(material.encode()).hexdigest()[:24]}",
                    capec_id=capec_id,
                    cwe_id=cwe_id,
                    provenance=provenance,
                )
            )
    return ParsedCAPECCatalog(
        source_release=release,
        patterns=tuple(sorted(patterns, key=lambda item: item.capec_id)),
        related_weaknesses=tuple(
            sorted(relations, key=lambda item: (item.capec_id, item.cwe_id, item.relation_id))
        ),
        steps=tuple(sorted(steps, key=lambda item: item.step_id)),
        prerequisites=tuple(sorted(prerequisites, key=lambda item: item.prerequisite_id)),
    )
