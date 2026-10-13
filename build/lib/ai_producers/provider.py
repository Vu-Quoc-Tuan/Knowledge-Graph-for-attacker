from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Literal, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

from openai import OpenAI, OpenAIError

from config import Settings


class AIConfigurationError(ValueError):
    """Raised when an AI producer is missing required configuration."""


class AIProviderError(RuntimeError):
    """Raised when an AI provider returns an unusable response."""


class StructuredChatProvider(Protocol):
    """Structural interface for AI chat backends used by the producers."""

    def structured_chat(
        self,
        messages: Sequence[Mapping[str, str]],
        *,
        schema_name: str,
        schema: Mapping[str, object],
    ) -> dict[str, object]: ...


@dataclass(frozen=True)
class AISettings:
    api_url: str
    api_key: str
    model_name: str
    embedding_model_name: str
    embedding_dimensions: int | None
    embedding_batch_size: int
    candidate_top_k: int
    max_relation_proposals: int
    max_payload_proposals: int
    max_source_chars: int
    embedding_cache: str
    timeout: float
    embedding_cache_max_entries: int | None = 50_000
    embedding_cache_ttl_seconds: float | None = 30 * 24 * 60 * 60
    embedding_api_url: str | None = None
    embedding_api_key: str | None = None
    embedding_truncate: str | None = None
    model_revision: str | None = None
    embedding_model_revision: str | None = None

    @property
    def resolved_embedding_api_url(self) -> str:
        return self.embedding_api_url or self.api_url

    @property
    def resolved_embedding_api_key(self) -> str:
        return self.embedding_api_key or self.api_key

    @property
    def producer_name(self) -> str:
        return self.model_name

    @property
    def model_version(self) -> str:
        return self.model_revision or "unknown-at-runtime"

    @property
    def embedding_model_version(self) -> str:
        return self.embedding_model_revision or "unknown-at-runtime"

    @property
    def relation_producer_version(self) -> str:
        """Version string recorded on relation proposals (chat + embedding model)."""
        return (
            f"{self.model_name}@{self.model_version};"
            f"{self.embedding_model_name}@{self.embedding_model_version}"
        )

    @property
    def payload_producer_version(self) -> str:
        """Version string recorded on payload proposals (chat model only)."""
        return f"{self.model_name}@{self.model_version}"

    def __post_init__(self) -> None:
        configured_at = datetime.now(timezone.utc).isoformat()
        if self.model_revision is None:
            object.__setattr__(self, "model_revision", f"configured-at:{configured_at}")
        if self.embedding_model_revision is None:
            object.__setattr__(
                self,
                "embedding_model_revision",
                f"configured-at:{configured_at}",
            )
        required_strings = {
            "AI_API_URL": self.api_url,
            "AI_API_KEY": self.api_key,
            "AI_MODEL_NAME": self.model_name,
            "AI_EMBEDDING_MODEL_NAME": self.embedding_model_name,
            "AI_EMBEDDING_CACHE": self.embedding_cache,
        }
        for variable, value in required_strings.items():
            if not isinstance(value, str) or not value.strip():
                raise AIConfigurationError(
                    f"{variable} must be a non-empty string"
                )
        endpoint_urls: dict[str, object] = {
            "AI_API_URL": self.api_url,
            "AI_EMBEDDING_API_URL": self.resolved_embedding_api_url,
        }
        for variable, endpoint_url in endpoint_urls.items():
            if (
                not isinstance(endpoint_url, str)
                or not endpoint_url.strip()
            ):
                raise AIConfigurationError(
                    f"{variable} must be a non-empty string"
                )
            parsed_url = urlsplit(endpoint_url)
            if (
                parsed_url.scheme not in {"http", "https"}
                or not parsed_url.netloc
                or parsed_url.query
                or parsed_url.fragment
            ):
                raise AIConfigurationError(
                    f"{variable} must be an absolute HTTP(S) base URL "
                    "without query or fragment"
                )
        embedding_api_key = self.resolved_embedding_api_key
        if (
            not isinstance(embedding_api_key, str)
            or not embedding_api_key.strip()
        ):
            raise AIConfigurationError(
                "AI_EMBEDDING_API_KEY must be a non-empty string"
            )
        if (
            self.embedding_truncate is not None
            and (
                not isinstance(self.embedding_truncate, str)
                or self.embedding_truncate not in {"NONE", "START", "END"}
            )
        ):
            raise AIConfigurationError(
                "AI_EMBEDDING_TRUNCATE must be NONE, START, or END when set"
            )
        positive_integers = {
            "AI_EMBEDDING_BATCH_SIZE": self.embedding_batch_size,
            "AI_CANDIDATE_TOP_K": self.candidate_top_k,
            "AI_MAX_RELATION_PROPOSALS": self.max_relation_proposals,
            "AI_MAX_PAYLOAD_PROPOSALS": self.max_payload_proposals,
            "AI_MAX_SOURCE_CHARS": self.max_source_chars,
        }
        for variable, value in positive_integers.items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise AIConfigurationError(
                    f"{variable} must be a positive integer"
                )
        if (
            self.embedding_dimensions is not None
            and (
                isinstance(self.embedding_dimensions, bool)
                or not isinstance(self.embedding_dimensions, int)
                or self.embedding_dimensions <= 0
            )
        ):
            raise AIConfigurationError(
                "AI_EMBEDDING_DIMENSIONS must be a positive integer when set"
            )
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise AIConfigurationError("HTTP_TIMEOUT must be positive")

    @classmethod
    def from_settings(cls, settings: Settings) -> "AISettings":
        embedding_truncate = settings.ai_embedding_truncate
        if isinstance(embedding_truncate, str):
            embedding_truncate = embedding_truncate.strip().upper() or None
        api_url = settings.ai_api_url or ""
        if api_url.rstrip("/").endswith("/api"):
            api_url = api_url.rstrip("/")[:-4] + "/v1"
        elif getattr(settings, "ai_provider_protocol", None) and getattr(settings, "ai_provider_protocol", "").upper() == "OLLAMA" and not api_url.rstrip("/").endswith("/v1"):
            api_url = f"{api_url.rstrip('/')}/v1"

        return cls(
            api_url=api_url,
            api_key=settings.ai_api_key or "",
            model_name=settings.ai_model_name or "",
            embedding_model_name=settings.ai_embedding_model_name or "",
            embedding_dimensions=settings.ai_embedding_dimensions,
            embedding_batch_size=settings.ai_embedding_batch_size or 0,
            candidate_top_k=settings.ai_candidate_top_k or 0,
            max_relation_proposals=settings.ai_max_relation_proposals or 0,
            max_payload_proposals=settings.ai_max_payload_proposals or 0,
            max_source_chars=settings.ai_max_source_chars or 0,
            embedding_cache=settings.ai_embedding_cache or "",
            embedding_cache_max_entries=settings.ai_embedding_cache_max_entries,
            embedding_cache_ttl_seconds=settings.ai_embedding_cache_ttl_seconds,
            timeout=settings.http_timeout,
            embedding_api_url=settings.ai_embedding_api_url,
            embedding_api_key=settings.ai_embedding_api_key,
            embedding_truncate=embedding_truncate,
        )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AIProviderError(
                "duplicate JSON key in AI provider response"
            )
        result[key] = value
    return result


def _decode_json_object(raw: str, *, context: str) -> dict[str, Any]:
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned.strip())
    try:
        result = json.loads(cleaned, object_pairs_hook=_unique_object)
    except AIProviderError:
        raise
    except (TypeError, ValueError) as exc:
        raise AIProviderError(f"{context} is not valid JSON") from exc
    if not isinstance(result, dict):
        raise AIProviderError(f"{context} must be a JSON object")
    return result


class OpenAICompatibleClient:
    """Strict project adapter over OpenAI-compatible SDK endpoints."""

    _SCHEMA_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

    def __init__(
        self,
        settings: AISettings,
        *,
        client_factory: Callable[..., OpenAI] = OpenAI,
    ) -> None:
        self.settings = settings
        common = {
            "timeout": settings.timeout,
            "max_retries": 0,
            "default_headers": {
                "User-Agent": f"cwe-kg/{settings.producer_name}",
            },
        }
        self._chat_client = client_factory(
            api_key=settings.api_key,
            base_url=settings.api_url,
            **common,
        )
        try:
            if (
                settings.resolved_embedding_api_url == settings.api_url
                and settings.resolved_embedding_api_key == settings.api_key
            ):
                self._embedding_client = self._chat_client
                self._clients = (self._chat_client,)
            else:
                self._embedding_client = client_factory(
                    api_key=settings.resolved_embedding_api_key,
                    base_url=settings.resolved_embedding_api_url,
                    **common,
                )
                self._clients = (
                    self._chat_client,
                    self._embedding_client,
                )
        except Exception:
            try:
                self._chat_client.close()
            except Exception:
                pass
            raise
        self._closed = False

    def __enter__(self) -> "OpenAICompatibleClient":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        first_failure: Exception | None = None
        for client in self._clients:
            try:
                client.close()
            except Exception as exc:
                if first_failure is None:
                    first_failure = exc
        if first_failure is not None:
            raise first_failure

    @staticmethod
    def _provider_error(operation: str, exc: OpenAIError) -> AIProviderError:
        status = getattr(exc, "status_code", None)
        detail = (
            f"HTTP {status}"
            if isinstance(status, int)
            else type(exc).__name__
        )
        return AIProviderError(
            f"AI provider request failed for {operation}: {detail}"
        )

    def embeddings(
        self,
        texts: Sequence[str],
        *,
        input_type: Literal["query", "passage"],
    ) -> list[list[float]]:
        if not texts or any(not isinstance(text, str) or not text for text in texts):
            raise ValueError("embedding input must contain non-empty strings")
        if input_type not in {"query", "passage"}:
            raise ValueError("input_type must be query or passage")
        request: dict[str, Any] = {
            "model": self.settings.embedding_model_name,
            "input": list(texts),
            "encoding_format": "float",
        }
        if self.settings.embedding_dimensions is not None:
            request["dimensions"] = self.settings.embedding_dimensions
        if self.settings.embedding_model_name.startswith("nvidia/"):
            extension: dict[str, str] = {"input_type": input_type}
            if self.settings.embedding_truncate is not None:
                extension["truncate"] = self.settings.embedding_truncate
            request["extra_body"] = extension
        try:
            raw_response = (
                self._embedding_client.embeddings.with_raw_response.create(
                    **request
                )
            )
        except OpenAIError as exc:
            raise self._provider_error("embeddings", exc) from exc
        payload = _decode_json_object(
            raw_response.text,
            context="embedding response",
        )
        data = payload.get("data")
        if not isinstance(data, list):
            raise AIProviderError("embedding response data must be an array")

        by_index: dict[int, list[float]] = {}
        vector_size: int | None = None
        for item in data:
            if not isinstance(item, dict):
                raise AIProviderError("embedding data items must be objects")
            index = item.get("index")
            if (
                isinstance(index, bool)
                or not isinstance(index, int)
                or index in by_index
            ):
                raise AIProviderError("embedding indexes must be unique integers")
            raw_vector = item.get("embedding")
            if not isinstance(raw_vector, list) or not raw_vector:
                raise AIProviderError("embedding vectors must be non-empty arrays")
            if any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                for value in raw_vector
            ):
                raise AIProviderError(
                    "embedding vectors must contain finite numbers"
                )
            vector = [float(value) for value in raw_vector]
            if vector_size is None:
                vector_size = len(vector)
            if len(vector) != vector_size:
                raise AIProviderError(
                    "embedding vectors must have consistent dimensions"
                )
            if (
                self.settings.embedding_dimensions is not None
                and len(vector) != self.settings.embedding_dimensions
            ):
                raise AIProviderError(
                    "embedding vector dimensions do not match configuration"
                )
            by_index[index] = vector

        expected_indexes = set(range(len(texts)))
        if set(by_index) != expected_indexes:
            raise AIProviderError(
                "embedding indexes must exactly match the requested inputs"
            )
        parsed = raw_response.parse()
        if len(parsed.data) != len(data):
            raise AIProviderError(
                "embedding response changed during SDK parsing"
            )
        return [by_index[index] for index in range(len(texts))]

    def structured_chat(
        self,
        messages: Sequence[Mapping[str, str]],
        *,
        schema_name: str,
        schema: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not self._SCHEMA_NAME.fullmatch(schema_name):
            raise ValueError("schema_name must be 1-64 identifier characters")
        try:
            raw_response = (
                self._chat_client.chat.completions.with_raw_response.create(
                    model=self.settings.model_name,
                    messages=[dict(message) for message in messages],
                    n=1,
                    stream=False,
                    response_format={
                        "type": "json_schema",
                        "json_schema": {
                            "name": schema_name,
                            "strict": True,
                            "schema": dict(schema),
                        },
                    },
                )
            )
        except OpenAIError as exc:
            try:
                raw_response = (
                    self._chat_client.chat.completions.with_raw_response.create(
                        model=self.settings.model_name,
                        messages=[dict(message) for message in messages],
                        n=1,
                        stream=False,
                        response_format={"type": "json_object"},
                    )
                )
            except OpenAIError:
                raise self._provider_error("chat/completions", exc) from exc
        payload = _decode_json_object(
            raw_response.text,
            context="structured chat response",
        )
        choices = payload.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            raise AIProviderError(
                "structured response must contain exactly one choice"
            )
        choice = choices[0]
        if not isinstance(choice, dict) or choice.get("finish_reason") != "stop":
            raise AIProviderError(
                "structured response finish_reason must be stop"
            )
        message = choice.get("message")
        if not isinstance(message, dict):
            raise AIProviderError("structured response message must be an object")
        if message.get("refusal"):
            raise AIProviderError("AI provider refused the structured request")
        content = message.get("content")
        if not isinstance(content, str):
            raise AIProviderError(
                "structured response message must contain string content"
            )

        parsed = raw_response.parse()
        if len(parsed.choices) != 1 or parsed.choices[0].finish_reason != "stop":
            raise AIProviderError(
                "structured response changed during SDK parsing"
            )

        return _decode_json_object(
            content,
            context="structured response content",
        )
