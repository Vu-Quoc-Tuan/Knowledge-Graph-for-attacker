"""Extract explicit CWE identifiers; fuzzy mapping is intentionally deferred to linking."""

from __future__ import annotations

import re

from ckg.domain.value_objects.evidence_span import EvidenceSpan
from ckg.extraction.models import ExtractionResult, FacetCandidate


def extract_explicit_cwes(text: str, *, evidence_id: str, content_digest: str, locator_prefix: str = "/text") -> ExtractionResult:
    candidates = []
    for match in re.finditer(r"\bCWE-([1-9][0-9]*)\b", text, flags=re.IGNORECASE):
        cwe_id = f"CWE-{match.group(1)}"
        candidates.append(FacetCandidate(kind="Weakness", value=cwe_id, normalized_id=cwe_id, extractor_name="explicit-cwe", extractor_version="1", evidence_spans=(EvidenceSpan(evidence_id=evidence_id, content_digest=content_digest, locator=f"{locator_prefix}/chars/{match.start()}-{match.end()}", excerpt=match.group(0)),), modality_scores={"explicit_identifier": 1.0}))
    return ExtractionResult(candidates=tuple(candidates))
