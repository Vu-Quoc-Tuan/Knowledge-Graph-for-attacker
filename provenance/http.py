from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

import requests

from provenance.models import BuildManifest, SourceSnapshot
from provenance.store import SnapshotStore, SnapshotStoreError
from utils.http import SourceFetchError, SourceResponse


class SourceTransport(Protocol):
    def fetch(self, url: str, params: Any = None) -> SourceResponse: ...

    def close(self) -> None: ...


def canonical_request_url(url: str, params: Any = None) -> str:
    prepared = requests.Request("GET", url, params=params).prepare()
    if not prepared.url:
        raise SourceFetchError(f"cannot construct request URL for {url}")
    return prepared.url


def _decode(content: bytes, encoding: str, url: str) -> str:
    try:
        return content.decode(encoding, errors="replace")
    except LookupError as exc:
        raise SourceFetchError(
            f"cannot decode source bytes from {url} as {encoding}: {exc}",
            url=url,
        ) from exc


class SnapshottingHttpClient:
    def __init__(
        self,
        store: SnapshotStore,
        transport: SourceTransport,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.transport = transport
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._sources: dict[str, SourceSnapshot] = {}

    def fetch(self, url: str, params: Any = None) -> SourceResponse:
        request_url = canonical_request_url(url, params)
        response = self.transport.fetch(url, params=params)
        digest = self.store.put(response.content)
        entry = SourceSnapshot(
            requestUrl=request_url,
            resolvedUrl=response.resolved_url,
            sha256=digest,
            byteLength=len(response.content),
            retrievedAt=self.clock(),
            etag=response.headers.get("ETag"),
            lastModified=response.headers.get("Last-Modified"),
            status=response.status_code,
            encoding=response.encoding or "utf-8",
        )
        previous = self._sources.get(request_url)
        if previous is not None and previous.sha256 != entry.sha256:
            raise SourceFetchError(
                f"source changed during build: {request_url}",
                url=request_url,
            )
        self._sources[request_url] = previous or entry
        return SourceResponse(
            request_url=request_url,
            resolved_url=response.resolved_url,
            status_code=response.status_code,
            headers=response.headers,
            content=response.content,
            encoding=response.encoding or "utf-8",
        )

    def get_bytes_and_text(self, url: str) -> tuple[bytes, str]:
        response = self.fetch(url)
        return response.content, _decode(
            response.content, response.encoding, response.request_url
        )

    def get_text(self, url: str) -> str:
        return self.get_bytes_and_text(url)[1]

    def get_json(self, url: str, params: Any = None) -> Any:
        response = self.fetch(url, params=params)
        text = _decode(
            response.content, response.encoding, response.request_url
        )
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise SourceFetchError(
                f"invalid JSON from {response.request_url}: {exc}",
                url=response.request_url,
            ) from exc

    def manifest(
        self,
        *,
        stage_summaries: dict[str, Any] | None = None,
        graph_counts: dict[str, Any] | None = None,
        graph_digest: str | None = None,
    ) -> BuildManifest:
        return BuildManifest(
            sources=sorted(
                self._sources.values(),
                key=lambda entry: entry.requestUrl,
            ),
            stageSummaries=stage_summaries,
            graphCounts=graph_counts,
            graphDigest=graph_digest,
        )

    def close(self) -> None:
        self.transport.close()


class ReplayHttpClient:
    def __init__(
        self,
        store: SnapshotStore,
        manifest: BuildManifest,
    ) -> None:
        self.store = store
        self.source_by_url = {
            entry.requestUrl: entry for entry in manifest.sources
        }

    def fetch(self, url: str, params: Any = None) -> SourceResponse:
        request_url = canonical_request_url(url, params)
        entry = self.source_by_url.get(request_url)
        if entry is None:
            raise SourceFetchError(
                f"{request_url}: not present in source manifest",
                url=request_url,
            )
        try:
            content = self.store.read(entry.sha256)
        except SnapshotStoreError as exc:
            raise SourceFetchError(str(exc), url=request_url) from exc
        if len(content) != entry.byteLength:
            raise SourceFetchError(
                f"{request_url}: byte length mismatch; expected "
                f"{entry.byteLength}, got {len(content)}",
                url=request_url,
            )
        return SourceResponse(
            request_url=request_url,
            resolved_url=entry.resolvedUrl,
            status_code=entry.status,
            headers={
                key: value
                for key, value in {
                    "ETag": entry.etag,
                    "Last-Modified": entry.lastModified,
                }.items()
                if value is not None
            },
            content=content,
            encoding=entry.encoding,
        )

    def get_bytes_and_text(self, url: str) -> tuple[bytes, str]:
        response = self.fetch(url)
        return response.content, _decode(
            response.content, response.encoding, response.request_url
        )

    def get_text(self, url: str) -> str:
        return self.get_bytes_and_text(url)[1]

    def get_json(self, url: str, params: Any = None) -> Any:
        response = self.fetch(url, params=params)
        text = _decode(
            response.content, response.encoding, response.request_url
        )
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise SourceFetchError(
                f"invalid JSON from {response.request_url}: {exc}",
                url=response.request_url,
            ) from exc

    def close(self) -> None:
        return None
