"""Source-tree compatibility wrapper for the packaged evaluation CLI."""

from ckg.evaluation.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
