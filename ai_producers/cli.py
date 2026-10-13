from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable

from neo4j.exceptions import Neo4jError, ServiceUnavailable
from pydantic import ValidationError

from ai_producers.embedding_cache import (
    EmbeddingCache,
    EmbeddingCacheError,
)
from ai_producers.models import AIContractError
from ai_producers.payload_producer import (
    PayloadAIProducer,
    PayloadProducerError,
)
from ai_producers.provider import (
    AIConfigurationError,
    AIProviderError,
    AISettings,
    OpenAICompatibleClient,
)
from ai_producers.relation_producer import (
    RelationAIProducer,
    RelationProducerError,
)
from ai_producers.retriever import EmbeddingRetriever, RetrievalError
from ai_producers.source import SourceDocumentError
from ai_producers.url_ingest import URLIngestError, URLWeaknessIngester
from config import Settings
from db.sink import GraphSink, Neo4jSink
from utils.http import HttpClient
from proposals.log import RelationLogError
from proposals.payload_log import PayloadLogError
from proposals.payload_service import (
    PayloadEventService,
    PayloadServiceError,
)
from proposals.policy import RelationPolicyError
from proposals.service import (
    RelationEventService,
    RelationServiceError,
)


def _parser(settings: Settings) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create human-gated proposals with configured AI models"
    )
    parser.add_argument(
        "--policy",
        default=settings.relation_policy,
    )
    parser.add_argument(
        "--relation-events",
        default=settings.relation_event_log,
    )
    parser.add_argument(
        "--payload-events",
        default=settings.payload_event_log,
    )
    parser.add_argument(
        "--repo-root",
        default=str(Path.cwd()),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    relations = commands.add_parser("relations")
    relations.add_argument("--weakness", required=True)
    relations.add_argument("--top-k", type=int)
    relations.add_argument("--write", action="store_true")

    revise_relation = commands.add_parser("revise-relation")
    revise_relation.add_argument("proposal_id")
    revise_relation.add_argument("--top-k", type=int)
    revise_relation.add_argument("--write", action="store_true")

    payloads = commands.add_parser("payloads")
    payloads.add_argument("--weakness", required=True)
    payloads.add_argument("--family-key", required=True)
    payloads.add_argument("--family-name", required=True)
    payloads.add_argument("--technology")
    payloads.add_argument("--source-ref", required=True)
    payloads.add_argument("--write", action="store_true")

    revise_payload = commands.add_parser("revise-payload")
    revise_payload.add_argument("proposal_id")
    revise_payload.add_argument("--write", action="store_true")

    ingest_url = commands.add_parser("ingest-url")
    ingest_url.add_argument("--url", required=True)
    ingest_url.add_argument("--write", action="store_true")

    suggest_vulns = commands.add_parser("suggest-vuln-relations")
    suggest_vulns.add_argument("--vulnerability", help="Target CVE ID to analyze relations for")
    suggest_vulns.add_argument("--min-score", type=float, default=0.7)
    suggest_vulns.add_argument("--write", action="store_true", help="Emit pending proposals to vulnerability event log")
    return parser


def _event_data(event: Any) -> dict[str, Any]:
    return event.model_dump(
        mode="json",
        exclude_none=True,
    )


def _relation_result(
    producer: RelationAIProducer,
    arguments: argparse.Namespace,
) -> dict[str, Any]:
    if arguments.command == "relations":
        if arguments.write:
            events = producer.write(arguments.weakness, arguments.top_k)
            return {
                "command": arguments.command,
                "writeRequested": True,
                "written": bool(events),
                "proposalCount": len(events),
                "events": [_event_data(event) for event in events],
            }
        preview = producer.preview(arguments.weakness, arguments.top_k)
    else:
        if arguments.write:
            event = producer.write_revision(
                arguments.proposal_id,
                arguments.top_k,
            )
            return {
                "command": arguments.command,
                "writeRequested": True,
                "written": True,
                "proposalCount": 1,
                "events": [_event_data(event)],
            }
        preview = producer.preview_revision(
            arguments.proposal_id,
            arguments.top_k,
        )
    return {
        "command": arguments.command,
        "writeRequested": False,
        "written": False,
        "wouldWrite": bool(preview.snapshots),
        "proposalCount": len(preview.snapshots),
        "weaknessId": preview.weakness_id,
        "proposals": [
            snapshot.model_dump(mode="json")
            for snapshot in preview.snapshots
        ],
        "retrievalScores": [
            {"weaknessId": weakness_id, "score": score}
            for weakness_id, score in preview.retrieval_scores
        ],
    }


def _payload_result(
    producer: PayloadAIProducer,
    arguments: argparse.Namespace,
) -> dict[str, Any]:
    if arguments.command == "payloads":
        values = {
            "weakness_id": arguments.weakness,
            "family_key": arguments.family_key,
            "family_name": arguments.family_name,
            "technology": arguments.technology,
            "source_ref": arguments.source_ref,
        }
        if arguments.write:
            events = producer.write(**values)
            return {
                "command": arguments.command,
                "writeRequested": True,
                "written": bool(events),
                "proposalCount": len(events),
                "events": [_event_data(event) for event in events],
            }
        preview = producer.preview(**values)
    else:
        if arguments.write:
            event = producer.write_revision(arguments.proposal_id)
            return {
                "command": arguments.command,
                "writeRequested": True,
                "written": True,
                "proposalCount": 1,
                "events": [_event_data(event)],
            }
        preview = producer.preview_revision(arguments.proposal_id)
    return {
        "command": arguments.command,
        "writeRequested": False,
        "written": False,
        "wouldWrite": bool(preview.snapshots),
        "proposalCount": len(preview.snapshots),
        "weaknessId": preview.weakness_id,
        "sourceRef": preview.source_ref,
        "proposals": [
            snapshot.model_dump(mode="json")
            for snapshot in preview.snapshots
        ],
    }


EXPECTED_ERRORS = (
    AIConfigurationError,
    AIProviderError,
    AIContractError,
    EmbeddingCacheError,
    RetrievalError,
    RelationProducerError,
    PayloadProducerError,
    SourceDocumentError,
    URLIngestError,
    RelationPolicyError,
    RelationLogError,
    RelationServiceError,
    PayloadLogError,
    PayloadServiceError,
    ValidationError,
    Neo4jError,
    ServiceUnavailable,
)


def _close_resources(*resources: object | None) -> list[str]:
    failures: list[str] = []
    for resource in resources:
        if resource is None:
            continue
        try:
            resource.close()
        except Exception as exc:
            failures.append(type(exc).__name__)
    return failures


def main(
    argv: list[str] | None = None,
    *,
    settings: Settings | None = None,
    sink_factory: Callable[[str, str, str], GraphSink] = Neo4jSink,
    client_factory: Callable[
        [AISettings], OpenAICompatibleClient
    ] = OpenAICompatibleClient,
    cache_factory: Callable[..., EmbeddingCache] = EmbeddingCache,
) -> int:
    try:
        configured = settings or Settings.from_env()
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"invalid environment configuration: {exc}", file=sys.stderr)
        return 2
    arguments = _parser(configured).parse_args(argv)
    sink: GraphSink | None = None
    client: OpenAICompatibleClient | None = None
    cache: EmbeddingCache | None = None
    result: dict[str, Any] | None = None
    operation_failed = False
    try:
        ai_settings = AISettings.from_settings(configured)
        sink = sink_factory(
            configured.neo4j_uri,
            configured.neo4j_user,
            configured.neo4j_password,
        )
        client = client_factory(ai_settings)
        if arguments.command in {"relations", "revise-relation"}:
            cache = cache_factory(
                ai_settings.embedding_cache,
                expected_dimensions=ai_settings.embedding_dimensions,
                max_entries=ai_settings.embedding_cache_max_entries,
                ttl_seconds=ai_settings.embedding_cache_ttl_seconds,
            )
            retriever = EmbeddingRetriever(
                client,
                cache,
                model_name=ai_settings.embedding_model_name,
                model_version=ai_settings.embedding_model_version,
                batch_size=ai_settings.embedding_batch_size,
                max_top_k=ai_settings.candidate_top_k,
            )
            result = _relation_result(
                RelationAIProducer(
                    sink,
                    retriever,
                    client,
                    RelationEventService(
                        arguments.policy,
                        arguments.relation_events,
                    ),
                    ai_settings,
                ),
                arguments,
            )
        elif arguments.command in {"payloads", "revise-payload"}:
            result = _payload_result(
                PayloadAIProducer(
                    sink,
                    client,
                    PayloadEventService(
                        arguments.payload_events,
                        arguments.repo_root,
                    ),
                    ai_settings,
                ),
                arguments,
            )
        elif arguments.command == "ingest-url":
            http = HttpClient(configured.http_timeout)
            try:
                ingester = URLWeaknessIngester(
                    http,
                    client,
                    ai_settings,
                    repo_root=arguments.repo_root,
                    registry_path=configured.local_weakness_registry,
                )
                entry = ingester.extract_draft(arguments.url)
                if arguments.write:
                    ingester.append_to_registry(
                        entry, configured.local_weakness_registry
                    )
                result = {
                    "action": "ingest_weakness_url",
                    "written": arguments.write,
                    "registry": configured.local_weakness_registry,
                    "entry": entry.model_dump(
                        mode="json", exclude_none=True
                    ),
                }
            finally:
                http.close()
        elif arguments.command == "suggest-vuln-relations":
            from ai_producers.vulnerability_relation_producer import (
                VulnerabilityRelationProducer,
            )
            from proposals.vulnerability_service import VulnerabilityEventService

            v_service = VulnerabilityEventService(configured.vulnerability_event_log)
            producer = VulnerabilityRelationProducer(sink, event_service=v_service)
            if arguments.vulnerability:
                candidates = producer.discover_relations_for_vulnerability(
                    arguments.vulnerability,
                    min_score=arguments.min_score,
                )
            else:
                candidates = []
                for node in sink.nodes("Vulnerability"):
                    vid = node.get("vulnId")
                    if vid:
                        candidates.extend(
                            producer.discover_relations_for_vulnerability(
                                vid, min_score=arguments.min_score
                            )
                        )

            emitted_ids = []
            if arguments.write and candidates:
                emitted_ids = producer.emit_proposals(candidates)

            result = {
                "action": "suggest_vulnerability_relations",
                "candidates_count": len(candidates),
                "written": arguments.write,
                "proposals_emitted": emitted_ids,
                "candidates": [
                    s.model_dump(mode="json", exclude_none=True)
                    for s in candidates
                ],
            }
    except EXPECTED_ERRORS as exc:
        print(str(exc), file=sys.stderr)
        operation_failed = True
    finally:
        cleanup_failures = _close_resources(cache, client, sink)
    if cleanup_failures:
        print(
            "resource cleanup failed: "
            + ", ".join(cleanup_failures),
            file=sys.stderr,
        )
        return 2
    if operation_failed:
        return 2
    if result is None:
        print("AI command produced no result", file=sys.stderr)
        return 2
    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
