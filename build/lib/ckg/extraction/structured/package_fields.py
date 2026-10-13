from ckg.extraction.models import ExtractionResult, FacetCandidate
from ckg.domain.value_objects.evidence_span import EvidenceSpan
from ckg.ingestion.cve.models import StructuredVulnerabilityRecord


def extract_affected_packages(record: StructuredVulnerabilityRecord, *, evidence_id: str, content_digest: str) -> ExtractionResult:
    candidates = []
    for index, affected in enumerate(record.affected):
        if affected.package_name:
            candidates.append(FacetCandidate(kind="Package", value=affected.package_name, normalized_id=None, extractor_name="structured-package", extractor_version="1", evidence_spans=(EvidenceSpan(evidence_id=evidence_id, content_digest=content_digest, locator=f"/affected/{index}/packageName"),), modality_scores={"structured_package": 1.0}))
    return ExtractionResult(candidates=tuple(candidates))
