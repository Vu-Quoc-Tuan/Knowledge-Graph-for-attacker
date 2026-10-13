"""Replay pinned canonical catalogs offline and report parser fidelity counts."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

from ckg.graph.memory import InMemoryGraphRepository
from ckg.ingestion.capec.importer import import_capec_catalog
from ckg.ingestion.capec.parser import parse_capec_catalog
from ckg.ingestion.cwe.importer import import_cwe_catalog
from ckg.ingestion.cwe.parser import parse_cwe_catalog
from ckg.provenance.store import SnapshotStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="return non-zero when the pinned release contains unresolved group memberships",
    )
    args = parser.parse_args(argv)
    mapping = yaml.safe_load((REPOSITORY_ROOT / "datasets/mappings/canonical_catalogs.yaml").read_text())
    catalogs = mapping["catalogs"]
    store = SnapshotStore(REPOSITORY_ROOT / "registry/upstream_snapshots")
    cwe_config = catalogs["cwe"]
    capec_config = catalogs["capec"]
    cwe = parse_cwe_catalog(store.read(cwe_config["catalog_xml_digest"]), source_snapshot_digest=cwe_config["catalog_xml_digest"], retrieved_at=datetime.fromisoformat(cwe_config["replay_recorded_at"].replace("Z", "+00:00")), source_url=cwe_config["catalog_url"])
    capec = parse_capec_catalog(store.read(capec_config["catalog_digest"]), source_snapshot_digest=capec_config["catalog_digest"], retrieved_at=datetime.fromisoformat(capec_config["replay_recorded_at"].replace("Z", "+00:00")), source_url=capec_config["catalog_url"])
    graph = InMemoryGraphRepository()
    cwe_report = import_cwe_catalog(graph, cwe)
    capec_report = import_capec_catalog(graph, capec)
    if cwe.source_release != cwe_config["release"]:
        raise ValueError(f"CWE parsed release mismatch: {cwe.source_release}")
    if capec.source_release != capec_config["release"]:
        raise ValueError(f"CAPEC parsed release mismatch: {capec.source_release}")
    if cwe_report.unresolved_relation_ids or capec_report.unresolved_cwe_ids:
        raise ValueError("canonical catalog replay has unresolved references")
    cwe_expected = cwe_config["expected_counts"]
    cwe_actual = {
        "weaknesses": cwe_report.weakness_count,
        "relations": cwe_report.relation_count,
        "groups": cwe_report.group_count,
        "source_memberships": len(cwe.group_memberships),
        "imported_memberships": cwe_report.membership_count,
        "unresolved_memberships": len(cwe_report.unresolved_group_memberships),
    }
    if cwe_actual != cwe_expected:
        raise ValueError(f"CWE replay count mismatch: expected {cwe_expected}, got {cwe_actual}")
    capec_expected = capec_config["expected_counts"]
    capec_actual = {
        "patterns": capec_report.pattern_count,
        "related_weaknesses": capec_report.related_weakness_count,
        "steps": capec_report.step_count,
        "prerequisites": capec_report.prerequisite_count,
    }
    if capec_actual != capec_expected:
        raise ValueError(f"CAPEC replay count mismatch: expected {capec_expected}, got {capec_actual}")
    unresolved_membership_targets = sorted({item[1] for item in cwe_report.unresolved_group_memberships})
    unresolved_membership_digest = hashlib.sha256("\n".join(unresolved_membership_targets).encode()).hexdigest()
    group_kinds = {node.node_id: node.label for node in graph.nodes() if node.label in {"CWECategory", "CWEView"}}
    unresolved_membership_diagnostics = [
        {
            "code": "MISSING_CWE_TARGET_IN_RELEASE",
            "group_id": group_id,
            "group_kind": group_kinds.get(group_id, "unknown"),
            "target_id": cwe_id,
            "view_id": view_id,
            "reason": "membership target is not present in the pinned CWE release",
        }
        for group_id, cwe_id, view_id in cwe_report.unresolved_group_memberships
    ]
    diagnostic_counts = dict(Counter(item["code"] for item in unresolved_membership_diagnostics))
    promotion_allowed = not unresolved_membership_diagnostics
    result = {
        "status": "PASS" if promotion_allowed else "PASS_WITH_DIAGNOSTICS",
        "promotion_allowed": promotion_allowed,
        "diagnostic_counts": diagnostic_counts,
        "cwe": {
            "release": cwe.source_release,
            "weaknesses": cwe_report.weakness_count,
            "relations": cwe_report.relation_count,
            "groups": cwe_report.group_count,
            "memberships": cwe_report.membership_count,
            "unresolved_membership_count": len(cwe_report.unresolved_group_memberships),
            "unresolved_membership_target_count": len(unresolved_membership_targets),
            "unresolved_membership_target_digest": f"sha256:{unresolved_membership_digest}",
            "unresolved_membership_target_sample": unresolved_membership_targets[:10],
            "unresolved_membership_diagnostics": unresolved_membership_diagnostics,
            "snapshot_digest": cwe_config["catalog_xml_digest"],
        },
        "capec": {
            "release": capec.source_release,
            "patterns": capec_report.pattern_count,
            "related_weaknesses": capec_report.related_weakness_count,
            "steps": capec_report.step_count,
            "prerequisites": capec_report.prerequisite_count,
            "snapshot_digest": capec_config["catalog_digest"],
        },
        "graph": {"nodes": len(graph.nodes()), "edges": len(graph.edges())},
    }
    print(json.dumps(result, sort_keys=True))
    return 2 if args.strict and not promotion_allowed else 0


if __name__ == "__main__":
    raise SystemExit(main())
