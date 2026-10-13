"""Small, auditable phrase rules for the first non-LLM extraction stage."""

from __future__ import annotations

import re

from ckg.domain.value_objects.evidence_span import EvidenceSpan
from ckg.extraction.models import ExtractionResult, FacetCandidate


_RULES: tuple[tuple[str, str, str, str], ...] = (
    ("Weakness", "Improper Restriction of XML External Entity Reference", "CWE-611", r"\bexternal entit(?:y|ies)\b|\bXXE\b"),
    ("Weakness", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "CWE-89", r"\bsql[- ]injection\b|\bsqli\b"),
    ("Weakness", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "CWE-79", r"\bcross[- ]site scripting\b|\bxss\b"),
    ("Weakness", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "CWE-22", r"\bpath traversal\b|\bdirectory traversal\b"),
    ("Weakness", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", "CWE-78", r"\bcommand injection\b|\bos command\b"),
    ("Weakness", "Improper Control of Generation of Code ('Code Injection')", "CWE-94", r"\bcode injection\b|\beval injection\b"),
    ("Technique", "SQL Injection", "TECH-SQL_INJECTION", r"\bsql[- ]injection\b|\bsqli\b"),
    ("Technique", "Cross-Site Scripting", "TECH-CROSS_SITE_SCRIPTING", r"\bcross[- ]site scripting\b|\bxss\b"),
    ("Technique", "Path Traversal", "TECH-PATH_TRAVERSAL", r"\bpath traversal\b|\bdirectory traversal\b"),
    ("Technique", "OutOfBand", "TECH-OUT_OF_BAND", r"\bout[- ]of[- ]band\b|\bOOB\b"),
    ("Technique", "Blind", "TECH-BLIND", r"\bblind\b"),
    ("Technique", "ErrorBased", "TECH-ERROR_BASED", r"\berror[- ]based\b"),
    ("Technique", "TimeBased", "TECH-TIME_BASED", r"\btime[- ](?:based|delay)\b"),
    ("CallbackChannel", "DNS", "CHANNEL-DNS", r"\b(?:DNS\s+(?:callback|interaction|channel|lookup|query|tunneling|egress))|\bout-of-band\s+DNS\b|\bDNS\s+callback\b"),
    ("CallbackChannel", "HTTP", "CHANNEL-HTTP", r"\b(?:HTTPS?\s+(?:callback|interaction|channel|out-of-band))|\bout-of-band\s+HTTPS?\b"),
    ("DataFormat", "XML", "FORMAT-XML", r"\bXML\b|\bexternal entit(?:y|ies)\b"),
    ("Component", "XMLParser", "COMPONENT-XML-PARSER", r"\bXML parser\b|\b(?:lxml|libxml2|xerces)\b"),
    ("Mechanism", "ExternalEntityResolution", "MECHANISM-EXTERNAL-ENTITY-RESOLUTION", r"\bexternal entit(?:y|ies)\b|\bDOCTYPE\b"),
    ("InputSurface", "XMLDocument", "INPUT-XML-DOCUMENT", r"\bXML document\b|\bXML payload\b"),
    ("Language", "PHP", "LANG-PHP", r"\bPHP\b|\.php\b"),
    ("Language", "Python", "LANG-PYTHON", r"\bPython\b"),
    ("Language", "Java", "LANG-JAVA", r"\bJava\b"),
    ("Language", "JavaScript", "LANG-JAVASCRIPT", r"\bJavaScript\b|\bNode\.?js\b"),
    ("Constraint", "ExternalEntitiesEnabled", "CONSTRAINT-EXTERNAL-ENTITIES-ENABLED", r"\bexternal entit(?:y|ies) (?:are |is )?enabled\b"),
    ("Constraint", "ExternalEntitiesDisabled", "CONSTRAINT-EXTERNAL-ENTITIES-DISABLED", r"\bexternal entit(?:y|ies) (?:are |is )?(?:disabled|disallowed)\b"),
    ("Constraint", "NetworkEgressAllowed", "CONSTRAINT-NETWORK-EGRESS-ALLOWED", r"\b(?:network|DNS) egress (?:is )?allowed\b"),
)


def _is_negated_or_patched(text: str, start: int) -> bool:
    window = text[max(0, start - 60):start].lower()
    for sep in (". ", ".\n", "! ", "? "):
        if sep in window:
            window = window.split(sep)[-1]
    return bool(re.search(r"\b(?:not|never|no longer)\s+vulnerable\s+(?:to\s+)?$|\b(?:fixed|patched|mitigated|resolved)\s+(?:in|by)?\s*$", window))


def extract_text_facets(
    text: str,
    *,
    evidence_id: str,
    content_digest: str,
    locator_prefix: str = "/text",
    extractor_name: str = "rule-facets",
    extractor_version: str = "1",
) -> ExtractionResult:
    """Extract only exact rule matches and return their source character spans."""
    candidates: list[FacetCandidate] = []
    for kind, value, normalized_id, pattern in _RULES:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            if kind == "Weakness" and _is_negated_or_patched(text, match.start()):
                continue
            candidates.append(
                FacetCandidate(
                    kind=kind,
                    value=value,
                    normalized_id=normalized_id,
                    extractor_name=extractor_name,
                    extractor_version=extractor_version,
                    evidence_spans=(EvidenceSpan(
                        evidence_id=evidence_id,
                        content_digest=content_digest,
                        locator=f"{locator_prefix}/chars/{match.start()}-{match.end()}",
                        excerpt=match.group(0),
                    ),),
                    modality_scores={"rule_text": 0.85},
                )
            )
    unique = {(item.kind, item.normalized_id, item.evidence_spans[0].locator): item for item in candidates}
    return ExtractionResult(candidates=tuple(unique.values()))
