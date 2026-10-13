from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ai_producers.retriever import CandidateWeakness
from proposals.models import Evidence


class EvidenceCatalogError(ValueError):
    """Raised when relation evidence is missing or misattributed."""


@dataclass(frozen=True)
class EvidenceEntry:
    key: str
    weakness_id: str
    source_ref: str
    excerpt: str

    def prompt_value(self) -> dict[str, str]:
        return {
            "weaknessId": self.weakness_id,
            "sourceRef": self.source_ref,
            "excerpt": self.excerpt,
        }

    def proposal_value(self) -> Evidence:
        return Evidence(
            sourceRef=self.source_ref,
            excerpt=self.excerpt,
        )


def _summary_entry(
    key: str,
    node: Mapping[str, object],
) -> EvidenceEntry:
    weakness_id = str(node.get("weaknessId") or "").strip()
    source_ref = str(node.get("sourceUrl") or "").strip()
    excerpt = str(node.get("summary") or "").strip()
    if not weakness_id or not source_ref or not excerpt:
        raise EvidenceCatalogError(
            f"{key}: Weakness evidence requires id, summary, and sourceUrl"
        )
    return EvidenceEntry(
        key=key,
        weakness_id=weakness_id,
        source_ref=source_ref,
        excerpt=excerpt,
    )


def relation_evidence_catalog(
    subject: Mapping[str, object],
    candidates: Sequence[CandidateWeakness],
) -> dict[str, EvidenceEntry]:
    catalog = {
        "subject.summary": _summary_entry("subject.summary", subject)
    }
    for candidate in candidates:
        key = f"{candidate.weakness_id}.summary"
        if key in catalog:
            raise EvidenceCatalogError(f"duplicate evidence key: {key}")
        entry = _summary_entry(key, candidate.node)
        if entry.weakness_id != candidate.weakness_id:
            raise EvidenceCatalogError(
                f"{key}: candidate identity does not match its node"
            )
        catalog[key] = entry
    return catalog

def select_relation_evidence(
    catalog: Mapping[str, EvidenceEntry],
    keys: Sequence[str],
    *,
    subject_id: str,
    object_id: str,
) -> list[Evidence]:
    provided = set(keys)
    unknown = sorted(provided - set(catalog))
    if unknown:
        raise EvidenceCatalogError(
            f"unknown relation evidence keys: {unknown}"
        )
    wrong_owner = sorted(
        key
        for key in provided
        if catalog[key].weakness_id not in {subject_id, object_id}
    )
    if wrong_owner:
        raise EvidenceCatalogError(
            f"relation evidence belongs to another candidate: {wrong_owner}"
        )

    # Required endpoint summaries are deterministic provenance even when the
    # model omits them from its selected keys.
    keys_set = set(provided)
    object_summary_key = f"{object_id}.summary"
    subject_summary_key = "subject.summary"
    if object_summary_key in catalog:
        keys_set.add(object_summary_key)
    if subject_summary_key in catalog:
        keys_set.add(subject_summary_key)

    selected = [catalog[key] for key in sorted(keys_set)]
    owners = {entry.weakness_id for entry in selected}
    if subject_id not in owners:
        raise EvidenceCatalogError(
            "relation proposal requires subject evidence"
        )
    if object_id not in owners:
        raise EvidenceCatalogError(
            "relation proposal requires object evidence"
        )
    if owners - {subject_id, object_id}:
        raise EvidenceCatalogError(
            "relation evidence belongs to another candidate"
        )
    return [entry.proposal_value() for entry in selected]
