from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

# it is important to import the models here so that they are registered with pydantic before any payloads are created
if TYPE_CHECKING:
    from db.sink import GraphSink

# lables for payloads that are not from a source but are generated locally
LOCAL_REVIEW_PAYLOAD_SOURCE = "local-human-review"
ASSERTED_TRUST_LEVEL = "asserted"
TESTED_VALIDATION_STATUS = "tested"

def payload_id(
    family_key: str,
    value: str,
    technology: str | None = None,
) -> str:
    digest = hashlib.sha256(
        (
            f"{family_key}\0"
            f"{technology or 'generic'}\0"
            f"{value}"
        ).encode("utf-8")
    ).hexdigest()[:16]
    return f"PAY-{digest}"

def payload_is_eligible_for_weakness(
    sink: GraphSink,
    payload_id_value: str,
    weakness_id: str,
) -> bool:
    """Return whether this payload may participate in a Weakness scenario."""
    payload = sink.get_node(
        "Payload",
        "payloadId",
        payload_id_value,
    )
    if payload is None:
        return False
    if payload.get("source") != LOCAL_REVIEW_PAYLOAD_SOURCE:
        return True
    return any(
        relation["props"].get("source")
        == LOCAL_REVIEW_PAYLOAD_SOURCE
        and relation["props"].get("trustLevel")
        == ASSERTED_TRUST_LEVEL
        for relation in sink.match_rels(
            "TARGETS",
            from_label="Payload",
            from_value=payload_id_value,
            to_label="Weakness",
            to_value=weakness_id,
        )
    )