from ckg.domain.value_objects.evidence_span import EvidenceSpan
from ckg.extraction.models import ExtractionResult, FacetCandidate
from ckg.ingestion.cve.models import StructuredVulnerabilityRecord


def extract_reported_weaknesses(record: StructuredVulnerabilityRecord, *, evidence_id: str, content_digest: str) -> ExtractionResult:
    """Structured CWE fields have direct source grounding and no LLM interpretation."""
    return ExtractionResult(candidates=tuple(
        FacetCandidate(kind="Weakness", value=item.cwe_id, normalized_id=item.cwe_id, extractor_name="structured-cve", extractor_version="1", evidence_spans=(EvidenceSpan(evidence_id=evidence_id, content_digest=content_digest, locator=item.json_pointer),), modality_scores={"structured_cwe": 1.0})
        for item in record.weaknesses
    ))
