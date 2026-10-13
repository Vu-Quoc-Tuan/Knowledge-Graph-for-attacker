"""Extract structured LocalWeaknessEntry drafts from advisory or article URLs."""

from __future__ import annotations

import hashlib
import html
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

import yaml
from pydantic import ValidationError

from ai_producers.models import (
    WeaknessIngestAIResponse,
    compact_validation_error,
    weakness_ingest_response_schema,
)
from ai_producers.prompts import weakness_ingest_messages
from ai_producers.provider import AISettings, StructuredChatProvider
from ingest.local_weakness_loader import LocalWeaknessEntry, LocalWeaknessRegistry
from utils.http import HttpClient, SourceFetchError
from utils.text import abridge, collapse


class URLIngestError(RuntimeError):
    """Raised when fetching or extracting weakness metadata from URL fails."""


def store_source_snapshot(
    root: str | Path,
    raw_bytes: bytes,
    suffix: str = ".bin",
) -> tuple[str, str]:
    """Atomically store source bytes under their SHA-256 object identity."""

    relative_path, digest = source_snapshot_identity(raw_bytes, suffix)
    relative = Path(relative_path)
    digest_hex = digest.removeprefix("sha256:")
    destination = Path(root).resolve() / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.read_bytes() != raw_bytes:
            raise URLIngestError(
                f"content-addressed object {relative.as_posix()} is corrupt"
            )
        return relative.as_posix(), digest

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{digest_hex}.",
        dir=destination.parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        if destination.exists():
            if destination.read_bytes() != raw_bytes:
                raise URLIngestError(
                    f"content-addressed object {relative.as_posix()} is corrupt"
                )
        else:
            os.replace(temporary_name, destination)
            temporary_name = ""
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)
    return relative.as_posix(), digest


def source_snapshot_identity(
    raw_bytes: bytes,
    suffix: str = ".bin",
) -> tuple[str, str]:
    """Return the future object path and digest without writing anything."""

    normalized_suffix = suffix.lower()
    if not re.fullmatch(r"\.[a-z0-9]{1,10}", normalized_suffix):
        raise URLIngestError(
            f"unsafe source snapshot suffix {suffix!r}"
        )
    digest_hex = hashlib.sha256(raw_bytes).hexdigest()
    digest = f"sha256:{digest_hex}"
    relative = Path(
        "registry/source_snapshots/objects"
    ) / f"{digest_hex}{normalized_suffix}"
    return relative.as_posix(), digest


def _atomic_write_text(path: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        temporary_name = ""
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def _snapshot_suffix(url: str) -> str:
    suffix = Path(urlparse(url).path).suffix.lower()
    if suffix in {".html", ".htm", ".json", ".md", ".txt", ".xml"}:
        return suffix
    return ".bin"


def _extract_html_title(html_text: str, default_url: str) -> str:
    match = re.search(r"<title\b[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
    if match:
        title = html.unescape(match.group(1)).strip()
        if title:
            return collapse(title)
    parsed = urlparse(default_url)
    return parsed.path.split("/")[-1] or parsed.netloc


def _strip_html(html_text: str) -> str:
    # Remove script and style tags completely
    text = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", html_text, flags=re.IGNORECASE | re.DOTALL)
    # Remove remaining HTML tags
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    return collapse(text)


def _next_local_weakness_id(registry_path: Path, namespace: str = "LOCAL") -> str:
    """Generate the next ID in sequence for a namespace (e.g. LOCAL-2026-001)."""
    current_year = datetime.now(timezone.utc).year
    prefix = f"{namespace}-{current_year}-"
    max_num = 0

    if registry_path.is_file():
        try:
            raw = yaml.safe_load(registry_path.read_text(encoding="utf-8")) or {}
            weaknesses = raw.get("weaknesses", [])
            for entry in weaknesses:
                wid = str(entry.get("weakness_id", ""))
                if wid.startswith(prefix):
                    parts = wid.split("-")
                    if len(parts) >= 3 and parts[-1].isdigit():
                        max_num = max(max_num, int(parts[-1]))
        except Exception:
            pass

    return f"{prefix}{max_num + 1:03d}"


class URLWeaknessIngester:
    def __init__(
        self,
        http_client: HttpClient,
        provider: StructuredChatProvider,
        settings: AISettings,
        repo_root: str | Path | None = None,
        registry_path: str | Path = "registry/weaknesses.yaml",
    ) -> None:
        self.http_client = http_client
        self.provider = provider
        self.settings = settings
        self.repo_root = Path(repo_root or Path.cwd()).resolve()
        self.registry_path = Path(registry_path)
        if not self.registry_path.is_absolute():
            self.registry_path = self.repo_root / self.registry_path
        self._pending_snapshots: dict[str, tuple[bytes, str]] = {}

    def extract_draft(self, url: str) -> LocalWeaknessEntry:
        """Fetch URL, calculate source hash, and use AI to extract weakness metadata."""
        try:
            raw_bytes, raw_text = self.http_client.get_bytes_and_text(url)
        except SourceFetchError as exc:
            raise URLIngestError(f"Cannot fetch URL {url}: {exc}") from exc

        snapshot_suffix = _snapshot_suffix(url)
        source_snapshot, source_hash = source_snapshot_identity(
            raw_bytes,
            snapshot_suffix,
        )
        self._pending_snapshots[source_hash] = (
            raw_bytes,
            snapshot_suffix,
        )
        page_title = _extract_html_title(raw_text, url)
        source_text = abridge(
            _strip_html(raw_text),
            self.settings.max_source_chars,
        )
        source_excerpt = abridge(
            collapse(raw_text),
            min(self.settings.max_source_chars, 1000),
        )

        messages = weakness_ingest_messages(
            source_url=url,
            page_title=page_title,
            source_text=source_text,
        )

        try:
            raw_response = self.provider.structured_chat(
                messages,
                schema_name="WeaknessIngestAIResponse",
                schema=weakness_ingest_response_schema(),
            )
            response = WeaknessIngestAIResponse.model_validate(raw_response)
        except (ValidationError, Exception) as exc:
            raise URLIngestError(
                f"AI extraction failed for {url}: {compact_validation_error(exc)}"
            ) from exc

        namespace = response.suggestedNamespace.upper().strip() or "LOCAL"
        weakness_id = _next_local_weakness_id(
            self.registry_path,
            namespace=namespace,
        )
        now_iso = datetime.now(timezone.utc).isoformat()

        entry_dict: dict[str, Any] = {
            "weakness_id": weakness_id,
            "namespace": namespace,
            "name": response.name,
            "summary": response.summary,
            "lifecycle_status": "proposed",
            "source_type": response.sourceType,
            "source_url": url,
            "source_title": page_title,
            "source_hash": source_hash,
            "source_snapshot": source_snapshot,
            "source_excerpt": source_excerpt,
            "declared_by": response.declaredBy,
            "created_at": now_iso,
            "technologies": response.technologies,
        }

        try:
            return LocalWeaknessEntry.model_validate(entry_dict)
        except ValidationError as exc:
            raise URLIngestError(
                f"Extracted metadata violates LocalWeaknessEntry schema: {compact_validation_error(exc)}"
            ) from exc

    def append_to_registry(
        self,
        entry: LocalWeaknessEntry,
        registry_path: str | Path,
    ) -> None:
        """Validate registry and append the new entry safely."""
        path = Path(registry_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if path.is_file():
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        else:
            raw = {"schema_version": 1, "weaknesses": []}

        raw.setdefault("schema_version", 1)
        raw.setdefault("weaknesses", [])

        # Check duplicate
        existing_ids = {item.get("weakness_id") for item in raw["weaknesses"] if isinstance(item, dict)}
        if entry.weakness_id in existing_ids:
            raise URLIngestError(f"Weakness ID {entry.weakness_id} already exists in registry")

        entry_data = entry.model_dump(mode="json", exclude_none=True)
        raw["weaknesses"].append(entry_data)

        # Validate complete registry before writing
        try:
            LocalWeaknessRegistry.model_validate(raw)
        except ValidationError as exc:
            raise URLIngestError(
                f"Registry validation failed: {compact_validation_error(exc)}"
            ) from exc

        if entry.source_snapshot is not None:
            pending = self._pending_snapshots.get(entry.source_hash or "")
            if pending is None:
                snapshot = self.repo_root / entry.source_snapshot
                if not snapshot.is_file():
                    raise URLIngestError(
                        "entry source snapshot was not produced by this "
                        "ingester and does not exist"
                    )
                actual = f"sha256:{hashlib.sha256(snapshot.read_bytes()).hexdigest()}"
                if actual != entry.source_hash:
                    raise URLIngestError(
                        "existing entry source snapshot digest does not match"
                    )
            else:
                raw_bytes, suffix = pending
                stored_ref, stored_hash = store_source_snapshot(
                    self.repo_root,
                    raw_bytes,
                    suffix,
                )
                if (
                    stored_ref != entry.source_snapshot
                    or stored_hash != entry.source_hash
                ):
                    raise URLIngestError(
                        "entry snapshot identity changed before persistence"
                    )

        _atomic_write_text(
            path,
            yaml.safe_dump(raw, allow_unicode=True, sort_keys=False),
        )
        if entry.source_hash:
            self._pending_snapshots.pop(entry.source_hash, None)
