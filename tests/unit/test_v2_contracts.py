import sys

import pytest
from pydantic import ValidationError


def test_fact_status_is_the_closed_research_lifecycle() -> None:
    from ckg.domain.enums.fact_status import FactStatus

    assert {status.value for status in FactStatus} == {
        "CANONICAL",
        "REPORTED",
        "EXTRACTED",
        "OBSERVED",
        "INFERRED",
        "SUPPORTED",
        "VALIDATED",
        "REJECTED",
    }


def test_evidence_span_requires_a_content_digest_and_locator() -> None:
    from ckg.domain.value_objects.evidence_span import EvidenceSpan

    with pytest.raises(ValidationError, match="sha256"):
        EvidenceSpan(
            evidence_id="EVID-001",
            content_digest="not-a-digest",
            locator="/records/0/description",
        )

    with pytest.raises(ValidationError):
        EvidenceSpan(
            evidence_id="EVID-001",
            content_digest="sha256:" + "a" * 64,
            locator="",
        )


def test_weakness_assertions_preserve_source_specific_identity() -> None:
    from ckg.domain.entities.assertion import WeaknessAssertion
    from ckg.domain.enums.fact_status import FactStatus
    from ckg.domain.value_objects.evidence_span import EvidenceSpan
    from ckg.domain.value_objects.provenance import Provenance

    span = EvidenceSpan(
        evidence_id="EVID-001",
        content_digest="sha256:" + "a" * 64,
        locator="/containers/cna/descriptions/0",
    )
    nvd = WeaknessAssertion(
        assertion_id="WAS-CVE-2026-0001-NVD-CWE-611",
        vulnerability_id="CVE-2026-0001",
        cwe_id="CWE-611",
        status=FactStatus.REPORTED,
        provenance=Provenance(
            source_id="NVD-CVE-2026-0001",
            source_kind="nvd",
            retrieved_at="2026-09-14T00:00:00Z",
        ),
        evidence_spans=[span],
    )
    ghsa = nvd.model_copy(
        update={
            "assertion_id": "WAS-CVE-2026-0001-GHSA-CWE-611",
            "provenance": nvd.provenance.model_copy(
                update={"source_id": "GHSA-2026-example"}
            ),
        }
    )

    assert nvd.assertion_id != ghsa.assertion_id
    assert nvd.provenance.source_id != ghsa.provenance.source_id


def test_domain_import_does_not_load_a_neo4j_driver() -> None:
    sys.modules.pop("neo4j", None)

    from ckg.domain.entities.cwe import CanonicalWeakness

    CanonicalWeakness(
        cwe_id="CWE-611",
        name="Improper Restriction of XML External Entity Reference",
        source_release="4.18",
        source_snapshot_digest="sha256:" + "b" * 64,
    )

    assert "neo4j" not in sys.modules
