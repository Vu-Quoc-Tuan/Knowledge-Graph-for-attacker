from unittest.mock import MagicMock, patch

from ckg.extraction.facets.model import extract_model_facets
from ckg.extraction.facets import extract_facets


def test_model_facets_skips_when_no_api_key(monkeypatch) -> None:
    monkeypatch.delenv("AI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    res = extract_model_facets(
        "A vulnerability in Python XML parser.",
        evidence_id="EVID-1",
        content_digest="sha256:" + "a" * 64,
    )
    assert len(res.candidates) == 0
    assert any("no AI_API_KEY" in a for a in res.abstentions)


def test_model_facets_extracts_and_locates_verbatim_quote() -> None:
    mock_payload = {
        "facets": [
            {
                "kind": "Technique",
                "value": "OutOfBand",
                "normalized_id": "TECH-OUT_OF_BAND",
                "exact_quote": "out-of-band callback",
                "confidence": 0.95,
            },
            {
                "kind": "Component",
                "value": "XMLParser",
                "normalized_id": "COMPONENT-XML-PARSER",
                "exact_quote": "lxml parser",
                "confidence": 0.9,
            },
        ]
    }

    mock_client = MagicMock()
    mock_choice = MagicMock()
    import json
    mock_choice.message.content = json.dumps(mock_payload)
    mock_client.chat.completions.create.return_value.choices = [mock_choice]

    text = "The issue allows an out-of-band callback when processed by the lxml parser."
    with patch("openai.OpenAI", return_value=mock_client):
        res = extract_model_facets(
            text,
            evidence_id="EVID-TEST",
            content_digest="sha256:" + "b" * 64,
            api_key="mock-key",
            model_name="test-model",
        )

    assert len(res.candidates) == 2
    cand1 = res.candidates[0]
    assert cand1.kind == "Technique"
    assert cand1.value == "OutOfBand"
    assert cand1.evidence_spans[0].excerpt == "out-of-band callback"
    assert cand1.evidence_spans[0].locator.startswith("/text/chars/")

    cand2 = res.candidates[1]
    assert cand2.kind == "Component"
    assert cand2.value == "XMLParser"
    assert cand2.evidence_spans[0].excerpt == "lxml parser"


def test_model_facets_abstains_when_quote_is_not_in_source() -> None:
    mock_client = MagicMock()
    mock_choice = MagicMock()
    import json
    mock_choice.message.content = json.dumps({"facets": [{
        "kind": "Technique", "value": "RemoteCodeExecution",
        "exact_quote": "remote code execution", "confidence": 0.99,
    }]})
    mock_client.chat.completions.create.return_value.choices = [mock_choice]

    with patch("openai.OpenAI", return_value=mock_client):
        result = extract_model_facets(
            "The application displays a welcome page.",
            evidence_id="EVID-TEST", content_digest="sha256:" + "e" * 64,
            api_key="mock-key", model_name="test-model",
        )

    assert result.candidates == ()
    assert any("unlocatable span" in item for item in result.abstentions)


def test_combined_extract_facets_deduplicates_overlapping_candidates() -> None:
    text = "Blind XXE in Python with DNS callback."
    res = extract_facets(
        text,
        evidence_id="EVID-1",
        content_digest="sha256:" + "c" * 64,
        use_model=False,
    )
    # Rule based found matches
    kinds = {c.kind for c in res.candidates}
    assert "Weakness" in kinds or "Technique" in kinds or "CallbackChannel" in kinds


def test_normalize_api_url_for_ollama() -> None:
    from ckg.extraction.facets.model import _normalize_api_url
    assert _normalize_api_url("https://ollama.com/api") == "https://ollama.com/v1"
    assert _normalize_api_url("https://ollama.com/api/") == "https://ollama.com/v1"
    assert _normalize_api_url("http://localhost:11434/api") == "http://localhost:11434/v1"
    assert _normalize_api_url("http://localhost:11434", protocol="OLLAMA") == "http://localhost:11434/v1"
    assert _normalize_api_url("https://api.openai.com/v1") == "https://api.openai.com/v1"
    assert _normalize_api_url(None) is None


def test_model_facets_handles_direct_list_and_markdown_fences() -> None:
    mock_payload = (
        "```json\n"
        "[\n"
        "  {\"kind\": \"Weakness\", \"value\": \"SQLInjection\", \"exact_quote\": \"SQL Injection\", \"confidence\": 0.99},\n"
        "  {\"kind\": \"Component\", \"value\": \"DockerTestLab\", \"exact_quote\": \"Docker Test Lab\", \"confidence\": 0.95}\n"
        "]\n"
        "```"
    )
    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = mock_payload
    mock_client.chat.completions.create.return_value.choices = [mock_choice]

    text = "Docker Test Lab is vulnerable to SQL Injection."
    with patch("openai.OpenAI", return_value=mock_client):
        res = extract_model_facets(
            text,
            evidence_id="EVID-TEST-1",
            content_digest="sha256:" + "0" * 64,
            api_key="mock-key",
            model_name="test-model",
        )

    assert len(res.candidates) == 2
    assert res.candidates[0].kind == "Weakness"
    assert res.candidates[0].value == "SQLInjection"
    assert res.candidates[0].evidence_spans[0].excerpt == "SQL Injection"
    assert res.candidates[1].kind == "Component"
    assert res.candidates[1].value == "DockerTestLab"
    assert res.candidates[1].evidence_spans[0].excerpt == "Docker Test Lab"
    assert len(res.abstentions) == 0
