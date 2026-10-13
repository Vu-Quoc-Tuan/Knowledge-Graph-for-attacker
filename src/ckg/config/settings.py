"""Application settings and environment configuration for v2 CKG."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .env import load_env


NEO4J_DEFAULT_URI = "bolt://localhost:7687"


@dataclass(frozen=True)
class Settings:
    # One superset is shared by the v2 API and legacy producers/UI.
    neo4j_uri: str = NEO4J_DEFAULT_URI
    neo4j_user: str = "neo4j"
    neo4j_password: str = "change-me-please"
    source_snapshot_root: str = "registry/upstream_snapshots"
    http_host: str = "127.0.0.1"
    http_port: int = 8088
    http_timeout: float = 60.0
    max_request_body_bytes: int = 2 * 1024 * 1024

    max_payloads_per_family: int = 400
    ai_embedding_batch_size: int = 20
    cwe_api_base: str = "https://cwe-api.mitre.org/api/v1"
    patt_contents_base: str = (
        "https://api.github.com/repos/swisskyrepo/PayloadsAllTheThings/contents"
    )
    wstg_contents_base: str = (
        "https://api.github.com/repos/OWASP/wstg/contents/document"
    )
    wstg_raw_base: str = (
        "https://raw.githubusercontent.com/OWASP/wstg/master/document"
    )
    wstg_checklist_url: str = (
        "https://raw.githubusercontent.com/OWASP/wstg/master/"
        "checklists/checklist.json"
    )
    local_weakness_registry: str = "registry/weaknesses.yaml"
    vulnerability_registry: str = "registry/vulnerabilities.yaml"
    relation_policy: str = "registry/relation_policy.yaml"
    event_log: str = "registry/event_log.jsonl"
    relation_event_log: str = "registry/event_log.jsonl"
    payload_event_log: str = "registry/payload_event_log.jsonl"
    vulnerability_event_log: str = "registry/vulnerability_event_log.jsonl"
    fragment_registry: str = "registry/scenario_fragments.yaml"
    oracle_registry: str = "registry/oracle_specs.yaml"
    ai_embedding_cache: str = ".cache/cwe-kg/embeddings.sqlite3"
    ai_embedding_cache_max_entries: int | None = 50_000
    ai_embedding_cache_ttl_seconds: float | None = 30 * 24 * 60 * 60

    # Model and AI configuration
    ai_provider_protocol: str | None = None
    ai_api_url: str | None = None
    ai_api_key: str | None = None
    ai_model_name: str | None = None
    ai_embedding_api_url: str | None = None
    ai_embedding_api_key: str | None = None
    ai_embedding_model_name: str | None = None
    ai_embedding_dimensions: int | None = None
    ai_embedding_truncate: str | None = None
    ai_candidate_top_k: int = 5
    ai_max_relation_proposals: int = 3
    ai_max_payload_proposals: int = 10
    ai_max_source_chars: int = 4000

    @classmethod
    def from_env(cls) -> Settings:
        load_env()
        raw_url = os.environ.get("AI_API_URL") or os.environ.get("AI_BASE_URL")
        protocol = os.environ.get("AI_PROVIDER_PROTOCOL")
        if raw_url:
            raw_url = raw_url.strip().rstrip("/")
            if raw_url.endswith("/api"):
                raw_url = raw_url[:-4] + "/v1"
            elif protocol and protocol.upper() == "OLLAMA" and not raw_url.endswith("/v1"):
                raw_url = f"{raw_url}/v1"

        return cls(
            neo4j_uri=os.environ.get("NEO4J_URI", cls.neo4j_uri),
            neo4j_user=os.environ.get("NEO4J_USER", cls.neo4j_user),
            neo4j_password=os.environ.get("NEO4J_PASSWORD", cls.neo4j_password),
            source_snapshot_root=os.environ.get("SOURCE_SNAPSHOT_ROOT", cls.source_snapshot_root),
            http_host=os.environ.get("CKG_HOST", cls.http_host),
            http_port=int(os.environ.get("CKG_PORT", str(cls.http_port))),
            http_timeout=float(os.environ.get("HTTP_TIMEOUT", str(cls.http_timeout))),
            max_request_body_bytes=int(os.environ.get("MAX_REQUEST_BODY_BYTES", str(cls.max_request_body_bytes))),
            max_payloads_per_family=int(os.environ.get("MAX_PAYLOADS_PER_FAMILY", cls.max_payloads_per_family)),
            ai_embedding_batch_size=int(os.environ.get("AI_EMBEDDING_BATCH_SIZE", cls.ai_embedding_batch_size)),
            cwe_api_base=os.environ.get("CWE_API_BASE", cls.cwe_api_base),
            patt_contents_base=os.environ.get("PATT_CONTENTS_BASE", cls.patt_contents_base),
            wstg_contents_base=os.environ.get("WSTG_CONTENTS_BASE", cls.wstg_contents_base),
            wstg_raw_base=os.environ.get("WSTG_RAW_BASE", cls.wstg_raw_base),
            wstg_checklist_url=os.environ.get("WSTG_CHECKLIST_URL", cls.wstg_checklist_url),
            local_weakness_registry=os.environ.get("LOCAL_WEAKNESS_REGISTRY", cls.local_weakness_registry),
            vulnerability_registry=os.environ.get("VULNERABILITY_REGISTRY", cls.vulnerability_registry),
            relation_policy=os.environ.get("RELATION_POLICY", cls.relation_policy),
            event_log=os.environ.get("EVENT_LOG", cls.event_log),
            relation_event_log=os.environ.get("RELATION_EVENT_LOG", os.environ.get("EVENT_LOG", cls.relation_event_log)),
            payload_event_log=os.environ.get("PAYLOAD_EVENT_LOG", cls.payload_event_log),
            vulnerability_event_log=os.environ.get("VULNERABILITY_EVENT_LOG", cls.vulnerability_event_log),
            fragment_registry=os.environ.get("FRAGMENT_REGISTRY", cls.fragment_registry),
            oracle_registry=os.environ.get("ORACLE_REGISTRY", cls.oracle_registry),
            ai_embedding_cache=os.environ.get("AI_EMBEDDING_CACHE", cls.ai_embedding_cache),
            ai_embedding_cache_max_entries=(
                int(os.environ["AI_EMBEDDING_CACHE_MAX_ENTRIES"])
                if os.environ.get("AI_EMBEDDING_CACHE_MAX_ENTRIES")
                else cls.ai_embedding_cache_max_entries
            ),
            ai_embedding_cache_ttl_seconds=(
                float(os.environ["AI_EMBEDDING_CACHE_TTL_SECONDS"])
                if os.environ.get("AI_EMBEDDING_CACHE_TTL_SECONDS")
                else cls.ai_embedding_cache_ttl_seconds
            ),
            ai_provider_protocol=protocol,
            ai_api_url=raw_url,
            ai_api_key=os.environ.get("AI_API_KEY") or os.environ.get("OPENAI_API_KEY"),
            ai_model_name=os.environ.get("AI_MODEL_NAME") or os.environ.get("AI_MODEL") or cls.ai_model_name,
            ai_embedding_api_url=os.environ.get("AI_EMBEDDING_API_URL", cls.ai_embedding_api_url),
            ai_embedding_api_key=os.environ.get("AI_EMBEDDING_API_KEY", cls.ai_embedding_api_key),
            ai_embedding_model_name=os.environ.get("AI_EMBEDDING_MODEL_NAME", cls.ai_embedding_model_name),
            ai_embedding_dimensions=(
                int(os.environ["AI_EMBEDDING_DIMENSIONS"])
                if os.environ.get("AI_EMBEDDING_DIMENSIONS")
                else cls.ai_embedding_dimensions
            ),
            ai_embedding_truncate=os.environ.get("AI_EMBEDDING_TRUNCATE", cls.ai_embedding_truncate),
            ai_candidate_top_k=int(os.environ.get("AI_CANDIDATE_TOP_K", cls.ai_candidate_top_k)),
            ai_max_relation_proposals=int(os.environ.get("AI_MAX_RELATION_PROPOSALS", cls.ai_max_relation_proposals)),
            ai_max_payload_proposals=int(os.environ.get("AI_MAX_PAYLOAD_PROPOSALS", cls.ai_max_payload_proposals)),
            ai_max_source_chars=int(os.environ.get("AI_MAX_SOURCE_CHARS", cls.ai_max_source_chars)),
        )
