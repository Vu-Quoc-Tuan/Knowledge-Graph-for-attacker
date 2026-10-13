"""Extract a small auditable PatchPattern facet family from unified diffs."""

from __future__ import annotations

from ckg.domain.value_objects.evidence_span import EvidenceSpan
from ckg.extraction.models import ExtractionResult, FacetCandidate
from ckg.extraction.patch.diff_parser import parse_unified_diff
from ckg.extraction.patch.semantic_diff import added_text


_PATTERNS = (
    ("PATCH-DISABLE-EXTERNAL-ENTITIES", "DisableExternalEntities", ("external_entities = false", "resolve_entities=false", "disallow-doctype")),
    ("PATCH-DISABLE-NETWORK-ACCESS", "DisableNetworkAccess", ("no_network=true", "network = false", "deny_network")),
    ("PATCH-ESCAPE-OUTPUT", "EscapeOutput", ("escape(", "html.escape", "encode_for_html")),
)


def extract_patch_patterns(diff: str, *, evidence_id: str, content_digest: str, extractor_version: str = "1") -> ExtractionResult:
    candidates: list[FacetCandidate] = []
    for hunk in parse_unified_diff(diff):
        text = added_text(hunk)
        for normalized_id, name, cues in _PATTERNS:
            if not any(cue in text for cue in cues):
                continue
            candidates.append(FacetCandidate(
                kind="PatchPattern",
                value=name,
                normalized_id=normalized_id,
                extractor_name="patch-pattern-rules",
                extractor_version=extractor_version,
                evidence_spans=(EvidenceSpan(evidence_id=evidence_id, content_digest=content_digest, locator=f"/diff/hunks/{hunk.ordinal}", excerpt=hunk.header),),
                modality_scores={"patch_diff": 0.90},
            ))
    return ExtractionResult(candidates=tuple(candidates))
