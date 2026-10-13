"""Model-backed facet extraction preserving source evidence spans."""

from __future__ import annotations

import json
import os
import re
from typing import Any

from ckg.domain.value_objects.evidence_span import EvidenceSpan
from ckg.extraction.models import ExtractionResult, FacetCandidate


_FACET_SCHEMA = {
    "type": "object",
    "properties": {
        "facets": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": [
                            "Weakness",
                            "Technique",
                            "CallbackChannel",
                            "Component",
                            "Mechanism",
                            "InputSurface",
                            "Language",
                            "Constraint",
                        ],
                    },
                    "value": {"type": "string"},
                    "normalized_id": {"type": ["string", "null"]},
                    "exact_quote": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": ["kind", "value", "exact_quote"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["facets"],
    "additionalProperties": False,
}

_SYSTEM_PROMPT = """You are a precision cybersecurity semantic facet extractor.
Extract security testing facets grounded in the provided vulnerability text.
Infer underlying security weaknesses and techniques even if explicit keywords (like "SQL injection" or "XSS") are omitted, as long as the vulnerability behavior, flaw, or mechanism is described.

For each extracted facet:
- kind: One of Weakness, Technique, CallbackChannel, Component, Mechanism, InputSurface, Language, Constraint.
- value: Canonical semantic concept name (e.g. SQLInjection, CommandInjection, CrossSiteScripting, PathTraversal, OutOfBand, Blind, XMLParser).
- exact_quote: The sentence or phrase from the text that provides the evidence for this claim.
- confidence: Float from 0.0 to 1.0.

CRITICAL: Output ONLY valid JSON conforming to the schema (e.g. {"facets": [...]}). Do NOT output markdown tables, commentary, or prose."""


def _find_span(text: str, quote: str, evidence_id: str, content_digest: str, locator_prefix: str) -> EvidenceSpan | None:
    if not quote or not quote.strip() or not text:
        return None
    cleaned_quote = quote.strip()

    # 1. Exact verbatim match
    idx = text.find(cleaned_quote)
    if idx >= 0:
        end_idx = idx + len(cleaned_quote)
        return EvidenceSpan(
            evidence_id=evidence_id,
            content_digest=content_digest,
            locator=f"{locator_prefix}/chars/{idx}-{end_idx}",
            excerpt=text[idx:end_idx],
        )

    # 2. Case-insensitive exact match
    match = re.search(re.escape(cleaned_quote), text, flags=re.IGNORECASE)
    if match:
        idx, end_idx = match.start(), match.end()
        return EvidenceSpan(
            evidence_id=evidence_id,
            content_digest=content_digest,
            locator=f"{locator_prefix}/chars/{idx}-{end_idx}",
            excerpt=text[idx:end_idx],
        )

    # 3. Flexible whitespace and punctuation match across words
    words = [re.escape(w) for w in re.findall(r"\w+", cleaned_quote) if len(w) > 1]
    if len(words) >= 2:
        pattern = r"[\s\W]+".join(words)
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            idx, end_idx = match.start(), match.end()
            return EvidenceSpan(
                evidence_id=evidence_id,
                content_digest=content_digest,
                locator=f"{locator_prefix}/chars/{idx}-{end_idx}",
                excerpt=text[idx:end_idx],
            )

    return None


def _normalize_api_url(api_url: str | None, protocol: str | None = None) -> str | None:
    if not api_url:
        return None
    url = api_url.strip().rstrip("/")
    if url.endswith("/api"):
        return url[:-4] + "/v1"
    if protocol and protocol.upper() == "OLLAMA" and not url.endswith("/v1"):
        return f"{url}/v1"
    return url


def extract_model_facets(
    text: str,
    *,
    evidence_id: str,
    content_digest: str,
    api_url: str | None = None,
    api_key: str | None = None,
    model_name: str | None = None,
    timeout: float = 30.0,
    locator_prefix: str = "/text",
    extractor_name: str = "model-facets",
    extractor_version: str = "1",
) -> ExtractionResult:
    """Extract multi-facet candidates using an OpenAI-compatible LLM provider."""
    raw_api_url = (
        api_url
        or os.environ.get("AI_API_URL")
        or os.environ.get("AI_BASE_URL")
        or os.environ.get("OPENAI_BASE_URL")
    )
    resolved_api_key = (
        api_key
        or os.environ.get("AI_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
    )
    resolved_model = (
        model_name
        or os.environ.get("AI_MODEL_NAME")
        or os.environ.get("AI_MODEL")
    )
    protocol = os.environ.get("AI_PROVIDER_PROTOCOL")
    resolved_api_url = _normalize_api_url(raw_api_url, protocol)

    if not resolved_api_key:
        return ExtractionResult(
            candidates=(),
            abstentions=("model extraction skipped: no AI_API_KEY configured",),
        )

    if not resolved_model:
        return ExtractionResult(
            candidates=(),
            abstentions=("model extraction skipped: no AI_MODEL_NAME configured",),
        )

    try:
        from openai import OpenAI

        client = OpenAI(base_url=resolved_api_url, api_key=resolved_api_key, timeout=timeout)
        try:
            response = client.chat.completions.create(
                model=resolved_model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": f"Vulnerability description to extract facets from:\n\n{text}"},
                ],
                response_format={
                    "type": "json_schema",
                    "json_schema": {"name": "facets", "schema": _FACET_SCHEMA, "strict": True},
                },
                temperature=0.0,
                max_tokens=1500,
            )
        except Exception:
            response = client.chat.completions.create(
                model=resolved_model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": f"Vulnerability description to extract facets from:\n\n{text}"},
                ],
                response_format={"type": "json_object"},
                temperature=0.0,
                max_tokens=1500,
            )
        msg = response.choices[0].message
        raw_content = (msg.content or "").strip()
        if not raw_content and getattr(msg, "reasoning", None):
            json_match = re.search(r"(\[[\s\S]*\]|\{[\s\S]*\})", str(msg.reasoning))
            if json_match:
                raw_content = json_match.group(1).strip()

        raw_content = re.sub(r"^```(?:json)?\s*", "", raw_content, flags=re.IGNORECASE)
        raw_content = re.sub(r"\s*```$", "", raw_content).strip()
        if not raw_content:
            return ExtractionResult(
                candidates=(),
                abstentions=("model extraction returned empty content",),
            )

        parsed: Any = None
        try:
            parsed = json.loads(raw_content)
        except json.JSONDecodeError:
            json_match = re.search(r"(\[[\s\S]*\]|\{[\s\S]*\})", raw_content)
            if json_match:
                parsed = json.loads(json_match.group(1).strip())
            elif "|" in raw_content:
                table_lines = [line.strip() for line in raw_content.splitlines() if "|" in line]
                if len(table_lines) >= 3:
                    header = [c.strip().lower() for c in table_lines[0].split("|")[1:-1]]
                    rows = []
                    for row in table_lines[2:]:
                        cols = [c.strip().strip("“”\"'") for c in row.split("|")[1:-1]]
                        if len(cols) >= len(header):
                            row_dict = dict(zip(header, cols))
                            if "kind" in row_dict and "value" in row_dict:
                                rows.append(row_dict)
                    if rows:
                        parsed = rows
            if parsed is None:
                raise

        if isinstance(parsed, list):
            raw_facets: list[dict[str, Any]] = parsed
        elif isinstance(parsed, dict):
            facets_val = parsed.get("facets")
            if isinstance(facets_val, list):
                raw_facets = facets_val
            elif isinstance(facets_val, dict):
                raw_facets = [facets_val]
            else:
                raw_facets = [parsed]
        else:
            raw_facets = []
    except Exception as exc:
        return ExtractionResult(
            candidates=(),
            abstentions=(f"model extraction failed: {type(exc).__name__}: {exc}",),
        )

    candidates: list[FacetCandidate] = []
    abstentions: list[str] = []

    for item in raw_facets:
        kind = str(item.get("kind", ""))
        value = str(item.get("value", ""))
        quote = str(item.get("exact_quote", ""))
        confidence = float(item.get("confidence", 0.85))
        span = _find_span(text, quote, evidence_id, content_digest, locator_prefix)
        if span is None:
            abstentions.append(f"unlocatable span for model facet: {kind}={value} quote={quote!r}")
            continue
        candidates.append(
            FacetCandidate(
                kind=kind,
                value=value,
                normalized_id=item.get("normalized_id"),
                extractor_name=extractor_name,
                extractor_version=extractor_version,
                evidence_spans=(span,),
                modality_scores={"rule_text": confidence},
            )
        )

    return ExtractionResult(
        candidates=tuple(candidates),
        abstentions=tuple(sorted(set(abstentions))),
    )
