"""Facet extractors: deterministic phrase rules and model-backed semantic extractors."""

from __future__ import annotations

from ckg.extraction.facets.model import extract_model_facets
from ckg.extraction.facets.rules import extract_text_facets
from ckg.extraction.facets.weakness import extract_explicit_cwes
from ckg.extraction.models import ExtractionResult


def extract_facets(
    text: str,
    *,
    evidence_id: str,
    content_digest: str,
    use_model: bool = False,
    **kwargs,
) -> ExtractionResult:
    """Extract facets using rule-based and optionally model-backed extractors."""
    rule_res = extract_text_facets(
        text, evidence_id=evidence_id, content_digest=content_digest, **kwargs
    )
    if not use_model:
        return rule_res

    model_res = extract_model_facets(
        text, evidence_id=evidence_id, content_digest=content_digest, **kwargs
    )
    # Deduplicate candidates across rules and model
    seen = {(c.kind, c.value, c.evidence_spans[0].locator) for c in rule_res.candidates}
    combined = list(rule_res.candidates)
    for c in model_res.candidates:
        key = (c.kind, c.value, c.evidence_spans[0].locator)
        if key not in seen:
            seen.add(key)
            combined.append(c)
    return ExtractionResult(
        candidates=tuple(combined),
        abstentions=tuple(sorted(set(rule_res.abstentions + model_res.abstentions))),
    )


__all__ = [
    "extract_explicit_cwes",
    "extract_facets",
    "extract_model_facets",
    "extract_text_facets",
]
