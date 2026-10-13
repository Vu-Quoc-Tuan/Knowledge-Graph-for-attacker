"""Command-line entrypoint for the offline historical evaluation feature."""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path

import yaml

from ckg.evaluation.historical import evaluate_cutoff, load_historical_records, parse_cutoffs
from ckg.evaluation.results import write_evaluation_artifacts


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("datasets/evaluation/manifest.yaml"))
    parser.add_argument("--snapshot-root", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=Path("datasets/evaluation/results"))
    parser.add_argument("--k", type=int, default=5, help="Number of ranked CWE predictions")
    parser.add_argument("--cutoff", action="append", dest="cutoffs", help="Override a cutoff; repeat for multiple values")
    parser.add_argument("--baseline", action="append", dest="baselines", help="Override a baseline; repeat for multiple values")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.k < 1:
        raise SystemExit("--k must be positive")
    manifest_path = args.manifest.resolve()
    manifest_payload = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest_payload, dict):
        raise SystemExit("manifest must be a YAML mapping")
    cutoff_values = args.cutoffs or manifest_payload.get("cutoffs")
    baseline_values = args.baselines or manifest_payload.get("baselines")
    if not isinstance(cutoff_values, list) or not cutoff_values:
        raise SystemExit("manifest must define a non-empty cutoffs list")
    if not isinstance(baseline_values, list) or not baseline_values:
        raise SystemExit("manifest must define a non-empty baselines list")
    cutoffs = parse_cutoffs(str(value) for value in cutoff_values)
    baselines = tuple(str(value) for value in baseline_values)
    records = load_historical_records(manifest_path, snapshot_root=args.snapshot_root)
    results = tuple(
        evaluate_cutoff(records, cutoff=cutoff, baseline=baseline, k=args.k)
        for cutoff in cutoffs
        for baseline in baselines
    )
    command = " ".join(
        shlex.quote(item)
        for item in ["ckg-evaluate-history", *(sys.argv[1:] if argv is None else argv)]
    )
    summary = write_evaluation_artifacts(
        args.output_dir,
        manifest_path=manifest_path,
        manifest_payload=manifest_payload,
        records=records,
        results=results,
        command=command,
    )
    print(yaml.safe_dump(summary, sort_keys=False, allow_unicode=True).rstrip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

