from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def relation_policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "relation_policy.yaml"
    path.write_text(
        """\
schema_version: 1
predicates:
  CHILD_OF:
    symmetric: false
    dimension_required: false
    allowed_dimensions: []
  SIMILAR_TO:
    symmetric: true
    dimension_required: true
    allowed_dimensions: [mechanism, input_vector, precondition, impact, detection_strategy]
""",
        encoding="utf-8",
    )
    return path
