from typing import Any

from utils.http import HttpClient, SourceFetchError
from utils.text import abridge, collapse
from db.sink import GraphSink
from ingest import mitre_fields
from schema.models import Weakness


HIERARCHY_VIEW_ID = "1000"


def _weakness_record(payload: Any, cwe_id: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SourceFetchError(f"MITRE returned a non-object for {cwe_id}")
    records = payload.get("Weaknesses")
    if not isinstance(records, list) or not records or not isinstance(records[0], dict):
        raise SourceFetchError(f"MITRE response has no Weaknesses[0] for {cwe_id}")
    return records[0]


def load_cwe(
    sink: GraphSink,
    http: HttpClient,
    cwe_id: str,
    cwe_api_base: str,
    *,
    extra_props: dict[str, Any] | None = None,
    fetched: set[str] | None = None,
) -> dict[str, int]:
    fetched = fetched if fetched is not None else set()
    child_of = 0

    def visit(current_id: str, current_extra: dict[str, Any] | None = None) -> None:
        nonlocal child_of
        if current_id in fetched:
            if current_extra:
                node = {"weaknessId": current_id, **current_extra}
                sink.merge_node("Weakness", "weaknessId", node)
            return
        fetched.add(current_id)
        number = current_id.removeprefix("CWE-")
        url = f"{cwe_api_base.rstrip('/')}/cwe/weakness/{number}"
        record = _weakness_record(http.get_json(url), current_id)
        actual_id = f"CWE-{record.get('ID', number)}"
        if actual_id != current_id:
            raise SourceFetchError(
                f"MITRE identity mismatch: requested {current_id}, received {actual_id}"
            )
        model = Weakness(
            weaknessId=current_id,
            namespace="CWE",
            externalId=current_id,
            cweId=current_id,
            name=str(record.get("Name") or ""),
            abstraction=str(record.get("Abstraction") or "Base"),
            summary=abridge(collapse(str(record.get("Description") or "")), 1000),
            lifecycleStatus="accepted",
            origin="MITRE",
            sourceType="authoritative",
            sourceUrl=url,
            likelihoodOfExploit=mitre_fields.likelihood(record),
            detectionMethods=mitre_fields.detection_methods(record) or None,
            mitigations=mitre_fields.mitigations(record) or None,
            demonstrativeExamples=mitre_fields.demonstrative_examples(record) or None,
            applicablePlatforms=mitre_fields.applicable_platforms(record) or None,
            **(current_extra or {}),
        )
        sink.merge_node("Weakness", "weaknessId", model.to_props())
        relations = record.get("RelatedWeaknesses") or []
        if not isinstance(relations, list):
            raise SourceFetchError(f"MITRE RelatedWeaknesses is not a list for {current_id}")
        for relation in relations:
            if not isinstance(relation, dict):
                continue
            if (
                str(relation.get("Nature")) != "ChildOf"
                or str(relation.get("ViewID")) != HIERARCHY_VIEW_ID
            ):
                continue
            parent_number = relation.get("CweID") or relation.get("CWE_ID")
            if not parent_number:
                continue
            parent_id = f"CWE-{parent_number}"
            visit(parent_id)
            sink.merge_rel(
                "Weakness",
                "weaknessId",
                current_id,
                "CHILD_OF",
                "Weakness",
                "weaknessId",
                parent_id,
                {"source": "MITRE", "viewId": HIERARCHY_VIEW_ID},
            )
            child_of += 1

    visit(cwe_id, extra_props)
    return {
        "weaknesses": len(fetched),
        "child_of": child_of,
    }
