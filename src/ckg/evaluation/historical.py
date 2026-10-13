"""Offline, temporal CVE-to-CWE evaluation over pinned source snapshots.

The evaluator deliberately uses the repository's production CVE parsers and
hash-addressed snapshot store.  It does not download data and it never treats
the current snapshot as a human-annotated gold set: labels on held-out CVEs
are reported as *future-observed* labels.
"""

from __future__ import annotations

import json
import hashlib
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

from ckg.evaluation.metrics import multi_label_f1, ranking_metrics
from ckg.graph.vectors.embeddings import lexical_embedding
from ckg.ingestion.cve.models import AffectedProduct, StructuredVulnerabilityRecord
from ckg.ingestion.cve.parser import parse_cve_services_record, parse_nvd_response
from ckg.provenance.store import SnapshotStore


_SUPPRESSED_STATES = frozenset({"REJECTED", "WITHDRAWN"})
_TOKEN_RE = re.compile(r"[a-z0-9]{2,}")


@dataclass(frozen=True)
class HistoricalRecord:
    """A parsed source observation with a stable snapshot identity."""

    key: str
    record_id: str
    source_kind: str
    source_digest: str
    source_url: str
    state: str
    published_at: datetime | None
    updated_at: datetime | None
    known_at: datetime | None
    title: str | None
    description: str | None
    products: tuple[AffectedProduct, ...]
    cwe_ids: frozenset[str]

    @property
    def active(self) -> bool:
        return self.state.upper() not in _SUPPRESSED_STATES

    @property
    def text(self) -> str:
        parts = [self.title or "", self.description or ""]
        for product in self.products:
            parts.extend(
                item
                for item in (
                    product.vendor,
                    product.product,
                    product.package_name,
                    product.ecosystem,
                    *product.aliases,
                )
                if item
            )
        return " ".join(parts)


@dataclass(frozen=True)
class HistoricalView:
    cutoff: datetime
    train: tuple[HistoricalRecord, ...]
    held_out: tuple[HistoricalRecord, ...]
    excluded: tuple[HistoricalRecord, ...]
    diagnostics: tuple[str, ...]


@dataclass(frozen=True)
class EvaluationResult:
    cutoff: datetime
    baseline: str
    task: str
    status: str
    n_train: int
    n_held_out: int
    n_judged: int
    k: int
    metrics: dict[str, float | None]
    predictions: dict[str, tuple[str, ...]]
    truth: dict[str, frozenset[str]]
    diagnostics: tuple[str, ...]


def _parse_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _manifest_payload(path: str | Path) -> dict[str, Any]:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("evaluation manifest must be a YAML mapping")
    return payload


def _resolve_snapshot_root(manifest_path: Path, configured: str | Path | None) -> Path:
    if configured is not None:
        return Path(configured).resolve()
    root_value = str(_manifest_payload(manifest_path).get("cve_snapshot", {}).get("root", ""))
    if not root_value:
        raise ValueError("manifest cve_snapshot.root is required")
    candidates = [Path(root_value), manifest_path.parent / root_value, manifest_path.parents[2] / root_value]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    raise FileNotFoundError(f"snapshot root does not exist: {root_value}")


def _record_from_source(record: StructuredVulnerabilityRecord, digest: str) -> HistoricalRecord:
    # The last source update is the conservative availability boundary.  Using
    # it instead of publication time prevents a current record update from
    # becoming training evidence for an earlier cutoff.
    known_at = record.updated_at or record.published_at
    cwe_ids = frozenset(
        weakness.cwe_id.upper()
        for weakness in record.weaknesses
        if weakness.cwe_id.upper().startswith("CWE-")
    )
    return HistoricalRecord(
        key=f"{record.record_id}::{digest}",
        record_id=record.record_id,
        source_kind=record.source_kind,
        source_digest=digest,
        source_url=record.source_url,
        state=record.state.upper(),
        published_at=record.published_at,
        updated_at=record.updated_at,
        known_at=known_at,
        title=record.title,
        description=record.description,
        products=record.affected,
        cwe_ids=cwe_ids,
    )


def load_historical_records(
    manifest_path: str | Path,
    *,
    snapshot_root: str | Path | None = None,
) -> tuple[HistoricalRecord, ...]:
    """Load and parse exactly the CVE objects listed in a manifest."""
    path = Path(manifest_path)
    payload = _manifest_payload(path)
    snapshot_config = payload.get("cve_snapshot")
    if not isinstance(snapshot_config, dict):
        raise ValueError("manifest cve_snapshot must be a mapping")
    digests = snapshot_config.get("object_digests")
    if not isinstance(digests, list) or not digests:
        raise ValueError("manifest cve_snapshot.object_digests must be non-empty")
    expected_count = snapshot_config.get("object_count")
    if expected_count is not None and int(expected_count) != len(digests):
        raise ValueError("manifest object_count does not match object_digests")
    inventory_digest = snapshot_config.get("inventory_digest")
    if not isinstance(inventory_digest, str) or not inventory_digest:
        raise ValueError("manifest inventory_digest is required")
    computed_inventory = "sha256:" + hashlib.sha256("\n".join(str(item) for item in digests).encode("utf-8")).hexdigest()
    if inventory_digest != computed_inventory:
        raise ValueError(
            "manifest inventory_digest does not match object_digests: "
            f"expected {inventory_digest}, computed {computed_inventory}"
        )

    store = SnapshotStore(_resolve_snapshot_root(path, snapshot_root))
    records: list[HistoricalRecord] = []
    for digest in digests:
        digest = str(digest)
        raw = store.read(digest)
        try:
            source_payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"snapshot {digest} is not JSON") from exc
        if not isinstance(source_payload, dict):
            raise ValueError(f"snapshot {digest} must contain a JSON object")
        source_url = f"snapshot://{digest}"
        if "cveMetadata" in source_payload:
            parsed = (parse_cve_services_record(source_payload, source_url=source_url),)
        elif "vulnerabilities" in source_payload:
            parsed = parse_nvd_response(source_payload, source_url=source_url)
        else:
            raise ValueError(f"snapshot {digest} is not a supported CVE Services or NVD payload")
        records.extend(_record_from_source(record, digest) for record in parsed)
    return tuple(sorted(records, key=lambda item: (item.key, item.record_id)))


def build_historical_view(records: Iterable[HistoricalRecord], *, cutoff: datetime) -> HistoricalView:
    """Split source observations without allowing post-cutoff records to train."""
    if cutoff.tzinfo is None:
        raise ValueError("cutoff must include timezone")
    normalized_cutoff = cutoff.astimezone(timezone.utc)
    train: list[HistoricalRecord] = []
    held_out: list[HistoricalRecord] = []
    excluded: list[HistoricalRecord] = []
    diagnostics: list[str] = []
    for record in records:
        if record.known_at is None:
            excluded.append(record)
        elif record.known_at <= normalized_cutoff:
            train.append(record)
        else:
            held_out.append(record)
    if excluded:
        diagnostics.append(f"excluded_undated_records={len(excluded)}")
    suppressed = sum(not record.active for record in (*train, *held_out))
    if suppressed:
        diagnostics.append(f"suppressed_source_records={suppressed}")
    return HistoricalView(
        cutoff=normalized_cutoff,
        train=tuple(sorted(train, key=lambda item: item.key)),
        held_out=tuple(sorted(held_out, key=lambda item: item.key)),
        excluded=tuple(sorted(excluded, key=lambda item: item.key)),
        diagnostics=tuple(diagnostics),
    )


def _tokens(value: str) -> frozenset[str]:
    return frozenset(_TOKEN_RE.findall(value.lower()))


def _product_tokens(product: AffectedProduct) -> frozenset[str]:
    values = [product.vendor or "", product.product or "", product.package_name or "", *product.aliases]
    return _tokens(" ".join(values))


def _identity_score(query: HistoricalRecord, candidate: HistoricalRecord) -> float:
    query_products = [_product_tokens(product) for product in query.products]
    candidate_products = [_product_tokens(product) for product in candidate.products]
    query_products = [tokens for tokens in query_products if tokens]
    candidate_products = [tokens for tokens in candidate_products if tokens]
    if not query_products or not candidate_products:
        return 0.0
    scores = []
    for left in query_products:
        for right in candidate_products:
            intersection = len(left & right)
            if intersection:
                scores.append(intersection / max(len(left), len(right)))
    return max(scores, default=0.0)


def _cosine(left: tuple[float, ...], right: tuple[float, ...]) -> float:
    return sum(a * b for a, b in zip(left, right))


def _text_score(query: HistoricalRecord, candidate: HistoricalRecord) -> float:
    return _cosine(lexical_embedding(query.text), lexical_embedding(candidate.text))


def _bm25_score(query: HistoricalRecord, candidate: HistoricalRecord, corpus: tuple[HistoricalRecord, ...]) -> float:
    """Small dependency-free BM25 implementation for the lexical baseline."""
    query_terms = _tokens(query.text)
    document_terms = _tokens(candidate.text)
    if not query_terms or not document_terms or not corpus:
        return 0.0
    document_lengths = [len(_tokens(record.text)) for record in corpus]
    average_length = sum(document_lengths) / len(document_lengths) if document_lengths else 0.0
    if not average_length:
        return 0.0
    document_frequency = {
        term: sum(term in _tokens(record.text) for record in corpus)
        for term in query_terms
    }
    score = 0.0
    k1 = 1.2
    b = 0.75
    length = len(document_terms)
    for term in query_terms:
        if term not in document_terms:
            continue
        idf = math.log1p((len(corpus) - document_frequency[term] + 0.5) / (document_frequency[term] + 0.5))
        term_frequency = 1
        denominator = term_frequency + k1 * (1 - b + b * length / average_length)
        score += idf * ((term_frequency * (k1 + 1)) / denominator)
    return score


def _candidate_score(query: HistoricalRecord, candidate: HistoricalRecord, baseline: str, cutoff: datetime) -> float:
    identity = _identity_score(query, candidate)
    text = _text_score(query, candidate)
    if baseline == "keyword-v1":
        return identity
    if baseline == "bm25-v1":
        raise ValueError("bm25 scoring requires the candidate corpus")
    if baseline == "lexical-hash-v1":
        return text
    if baseline in {"graph-only-v1", "graph-temporal-v1"}:
        return identity
    if baseline == "graph-evidence-v1":
        return identity * (1.0 + min(len(candidate.cwe_ids), 3) / 10.0)
    if baseline == "graph-provenance-v1":
        provenance = 0.1 if candidate.source_digest and candidate.source_url else 0.0
        provenance += 0.1 if candidate.updated_at else 0.0
        return identity + provenance
    if baseline == "graph-full-v1":
        recency = 0.0
        if candidate.known_at is not None:
            age_days = max((cutoff - candidate.known_at).total_seconds() / 86400, 0.0)
            recency = 1.0 / (1.0 + math.log1p(age_days))
        return (0.55 * identity) + (0.35 * text) + (0.05 * recency) + (0.05 if candidate.source_digest else 0.0)
    raise ValueError(f"unknown historical baseline: {baseline}")


def predict_weaknesses(
    query: HistoricalRecord,
    view: HistoricalView,
    *,
    baseline: str,
    k: int = 5,
) -> tuple[str, ...]:
    """Rank CWE labels propagated through the temporally visible graph view."""
    if k < 1:
        raise ValueError("k must be positive")
    label_scores: dict[str, float] = {}
    candidates = tuple(record for record in view.train if record.active and record.cwe_ids)
    for candidate in candidates:
        score = (
            _bm25_score(query, candidate, candidates)
            if baseline == "bm25-v1"
            else _candidate_score(query, candidate, baseline, view.cutoff)
        )
        if score <= 0:
            continue
        for cwe_id in candidate.cwe_ids:
            label_scores[cwe_id] = max(label_scores.get(cwe_id, 0.0), score)
    return tuple(
        cwe_id
        for cwe_id, _ in sorted(label_scores.items(), key=lambda item: (-item[1], item[0]))[:k]
    )


def evaluate_cutoff(
    records: Iterable[HistoricalRecord],
    *,
    cutoff: datetime,
    baseline: str,
    k: int = 5,
) -> EvaluationResult:
    """Evaluate future-observed CWE labels at one temporal cutoff."""
    view = build_historical_view(records, cutoff=cutoff)
    predictions: dict[str, tuple[str, ...]] = {}
    truth: dict[str, frozenset[str]] = {}
    for record in view.held_out:
        if not record.active or not record.cwe_ids:
            continue
        truth[record.key] = record.cwe_ids
        predictions[record.key] = predict_weaknesses(record, view, baseline=baseline, k=k)
    ranking = ranking_metrics(predictions, truth, k=k)
    f1 = multi_label_f1(
        {key: frozenset(value) for key, value in predictions.items()},
        truth,
    )
    metrics: dict[str, float | None] = {**ranking, **f1}
    diagnostics = list(view.diagnostics)
    diagnostics.append("held_out_labels_are_future_observed_not_human_gold")
    if not truth:
        status = "not_evaluable"
        diagnostics.append("no_active_held_out_records_with_CWE_labels")
    else:
        # An empty prediction is an observed model failure (zero recall), not
        # a missing evaluation.  This distinction matters for ablations.
        status = "evaluated"
        if not any(predictions.values()):
            diagnostics.append("no_temporally_visible_CWE_evidence_for_predictions")
    return EvaluationResult(
        cutoff=view.cutoff,
        baseline=baseline,
        task="cve_to_cwe_temporal_link_prediction",
        status=status,
        n_train=len(view.train),
        n_held_out=len(view.held_out),
        n_judged=len(truth),
        k=k,
        metrics=metrics,
        predictions=predictions,
        truth=truth,
        diagnostics=tuple(diagnostics),
    )


def parse_cutoffs(values: Iterable[str]) -> tuple[datetime, ...]:
    parsed = tuple(_parse_timestamp(value) for value in values)
    if any(value is None for value in parsed):
        raise ValueError("cutoffs must be ISO-8601 timestamps")
    return tuple(value.astimezone(timezone.utc) for value in parsed if value is not None)
