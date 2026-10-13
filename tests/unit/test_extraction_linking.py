from datetime import datetime, timezone


def _repository():
    from ckg.domain.entities.cwe import CanonicalWeakness
    from ckg.domain.entities.cve import Vulnerability
    from ckg.graph.memory import InMemoryGraphRepository
    from ckg.graph.models import GraphNode

    repository = InMemoryGraphRepository()
    repository.atomic_write(nodes=[
        GraphNode(label="CWE", node_id="CWE-611", props=CanonicalWeakness(cwe_id="CWE-611", name="XML External Entity", source_release="4.20", source_snapshot_digest="sha256:" + "a" * 64, mapping_usage="Allowed").model_dump(mode="json")),
        GraphNode(label="CWE", node_id="CWE-79", props=CanonicalWeakness(cwe_id="CWE-79", name="Cross-site Scripting", source_release="4.20", source_snapshot_digest="sha256:" + "a" * 64, mapping_usage="Allowed").model_dump(mode="json")),
        GraphNode(label="CVE", node_id="CVE-2026-10001", props=Vulnerability(vulnerability_id="CVE-2026-10001", title="Test", published_at=datetime(2026, 1, 1, tzinfo=timezone.utc)).model_dump(mode="json")),
    ], edges=[])
    return repository


def test_rule_extraction_grounded_in_exact_text_spans_for_blind_oob_dns() -> None:
    from ckg.extraction.facets.rules import extract_text_facets

    result = extract_text_facets("A blind XML parser resolves an external entity and triggers an out-of-band DNS callback.", evidence_id="EVID-test", content_digest="sha256:" + "b" * 64)
    labels = {(item.kind, item.normalized_id) for item in result.candidates}

    assert ("Technique", "TECH-BLIND") in labels
    assert ("Technique", "TECH-OUT_OF_BAND") in labels
    assert ("CallbackChannel", "CHANNEL-DNS") in labels
    assert ("DataFormat", "FORMAT-XML") in labels
    assert ("Component", "COMPONENT-XML-PARSER") in labels
    assert ("Mechanism", "MECHANISM-EXTERNAL-ENTITY-RESOLUTION") in labels
    assert all("/text/chars/" in item.evidence_spans[0].locator for item in result.candidates)


def test_cwe_linking_uses_explicit_identifier_and_creates_an_extracted_assertion() -> None:
    from ckg.extraction.facets.weakness import extract_explicit_cwes
    from ckg.linking.cwe.candidate_generator import generate_candidates
    from ckg.linking.cwe.resolver import resolve_weakness

    repository = _repository()
    candidate = extract_explicit_cwes("The issue maps to CWE-611.", evidence_id="EVID-test", content_digest="sha256:" + "b" * 64).candidates[0]
    assert generate_candidates(repository, candidate) == (("CWE-611", 1.0),)

    result = resolve_weakness(repository, vulnerability_id="CVE-2026-10001", candidate=candidate, cwe_id="CWE-611", retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc))

    assert result.abstention is None
    assert result.score.relevance == 1.0
    assert result.score.evidence_coverage > 0.0
    assert repository.nodes("WeaknessAssertion")[0].props["status"] == "EXTRACTED"


def test_missing_modalities_abstain_instead_of_producing_default_confidence() -> None:
    from ckg.extraction.models import FacetCandidate
    from ckg.domain.value_objects.evidence_span import EvidenceSpan
    from ckg.linking.cwe.resolver import resolve_weakness
    from ckg.linking.cwe.scorer import score_modalities

    repository = _repository()
    candidate = FacetCandidate(kind="Weakness", value="maybe XML issue", normalized_id="CWE-611", extractor_name="test", extractor_version="1", evidence_spans=(EvidenceSpan(evidence_id="EVID-test", content_digest="sha256:" + "b" * 64, locator="/text/0"),), modality_scores={})
    score = score_modalities({})
    result = resolve_weakness(repository, vulnerability_id="CVE-2026-10001", candidate=candidate, cwe_id="CWE-611", retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc))

    assert score.relevance is None
    assert score.evidence_coverage == 0.0
    assert result.assertion_id is None
    assert result.abstention == "insufficient relevance or evidence coverage"


def test_cwe_candidate_generation_honors_canonical_mapping_usage() -> None:
    from ckg.domain.entities.cwe import CanonicalWeakness
    from ckg.extraction.facets.weakness import extract_explicit_cwes
    from ckg.graph.models import GraphNode
    from ckg.linking.cwe.candidate_generator import generate_candidates

    repository = _repository()
    repository.atomic_write(nodes=[GraphNode(label="CWE", node_id="CWE-999", props=CanonicalWeakness(cwe_id="CWE-999", name="Do not map", source_release="4.20", source_snapshot_digest="sha256:" + "a" * 64, mapping_usage="Prohibited").model_dump(mode="json"))], edges=[])
    candidate = extract_explicit_cwes("CWE-999", evidence_id="EVID-test", content_digest="sha256:" + "b" * 64).candidates[0]

    assert generate_candidates(repository, candidate) == ()


def test_technique_and_context_extraction_are_asserted_separately_from_source_ontology() -> None:
    from ckg.domain.entities.technique import Technique
    from ckg.extraction.facets.rules import extract_text_facets
    from ckg.graph.models import GraphNode
    from ckg.linking.context.assertions import materialize_context_assertion
    from ckg.linking.technique.resolver import resolve_technique

    repository = _repository()
    repository.atomic_write(nodes=[
        GraphNode(label="Technique", node_id="TECH-OUT_OF_BAND", props=Technique(technique_id="TECH-OUT_OF_BAND", name="OutOfBand").model_dump(mode="json")),
        GraphNode(label="CallbackChannel", node_id="CHANNEL-DNS", props={"channel_id": "CHANNEL-DNS", "name": "DNS"}),
    ], edges=[])
    candidates = extract_text_facets("An out-of-band DNS callback occurs.", evidence_id="EVID-test", content_digest="sha256:" + "b" * 64).candidates
    technique = next(item for item in candidates if item.normalized_id == "TECH-OUT_OF_BAND")
    channel = next(item for item in candidates if item.normalized_id == "CHANNEL-DNS")

    technique_result = resolve_technique(repository, vulnerability_id="CVE-2026-10001", candidate=technique, technique_id="TECH-OUT_OF_BAND", relation="DETECTABLE_BY", retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc))
    context_id = materialize_context_assertion(repository, vulnerability_id="CVE-2026-10001", candidate=channel, context_label="CallbackChannel", retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc))

    assert technique_result.abstention is None
    assert context_id is not None
    assert len(repository.nodes("TechniqueAssertion")) == 1
    assert len(repository.nodes("ContextAssertion")) == 1


def test_constraint_phrase_creates_a_three_valued_constraint_node() -> None:
    from ckg.constraints.evaluator import EnvironmentSnapshot, evaluate
    from ckg.extraction.facets.rules import extract_text_facets
    from ckg.linking.constraint.resolver import materialize_constraint

    repository = _repository()
    candidate = next(item for item in extract_text_facets("External entities are enabled.", evidence_id="EVID-test", content_digest="sha256:" + "b" * 64).candidates if item.kind == "Constraint")
    constraint_id = materialize_constraint(repository, vulnerability_id="CVE-2026-10001", candidate=candidate, retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc))

    assert constraint_id == "CONSTRAINT-EXTERNAL-ENTITIES-ENABLED"
    constraint = repository.nodes("ApplicabilityConstraint")[0]
    assert evaluate(constraint.props["expression"], EnvironmentSnapshot(environment_id="ENV", configuration={"external_entities": None})).applicability.value == "UNKNOWN"


def test_patch_pattern_extraction_keeps_a_hunk_locator() -> None:
    from ckg.extraction.patch.pattern_extractor import extract_patch_patterns

    result = extract_patch_patterns("@@ -1 +1 @@\n-resolve_entities=true\n+resolve_entities=false", evidence_id="EVID-PATCH", content_digest="sha256:" + "c" * 64)

    assert [(item.normalized_id, item.evidence_spans[0].locator) for item in result.candidates] == [("PATCH-DISABLE-EXTERNAL-ENTITIES", "/diff/hunks/0")]


def test_patch_pattern_is_grounded_and_available_to_historical_retrieval() -> None:
    from ckg.extraction.patch.pattern_extractor import extract_patch_patterns
    from ckg.linking.patch.resolver import materialize_patch_pattern

    repository = _repository()
    candidate = extract_patch_patterns(
        "@@ -1 +1 @@\n-resolve_entities=true\n+resolve_entities=false",
        evidence_id="EVID-PATCH",
        content_digest="sha256:" + "c" * 64,
    ).candidates[0]
    pattern_id = materialize_patch_pattern(
        repository,
        vulnerability_id="CVE-2026-10001",
        candidate=candidate,
        retrieved_at=datetime(2026, 9, 14, tzinfo=timezone.utc),
    )

    assert pattern_id == "PATCH-DISABLE-EXTERNAL-ENTITIES"
    edge = repository.edges("HAS_PATCH_PATTERN")[0]
    assert edge.props["evidence_spans"][0]["locator"] == "/diff/hunks/0"


def test_negation_and_non_callback_http_are_not_extracted() -> None:
    from ckg.extraction.facets.rules import extract_text_facets

    text = "The service accepts standard HTTP requests and is not vulnerable to SQL injection."
    result = extract_text_facets(text, evidence_id="EVID-1", content_digest="sha256:" + "d" * 64)
    kinds_and_ids = {(c.kind, c.normalized_id) for c in result.candidates}

    assert ("Weakness", "CWE-89") not in kinds_and_ids
    assert ("CallbackChannel", "CHANNEL-HTTP") not in kinds_and_ids
